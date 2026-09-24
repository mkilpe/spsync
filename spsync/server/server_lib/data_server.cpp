#include "data_server.hpp"
#include "data_connection.hpp"
#include "record_server_link.hpp"

#include <spsync/core/error.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/crypto/private_data_access.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/network/encryption/framing.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

#include <asio/steady_timer.hpp>

#include <atomic>
#include <filesystem>
#include <map>
#include <mutex>
#include <set>

namespace securepath::sync {

asio::ip::tcp::endpoint data_server_params::create_endpoint() const {
	return data_endpoint.value_or(asio::ip::tcp::endpoint(asio::ip::address_v4::any(), data_port));
}

namespace {

/// a client on the data listener: the transport around data_connection
class data_server_client
	: public data_connection
	, public network::encrypted_connection
{
public:
	data_server_client(network::context& c, std::shared_ptr<network::encrypted_server> server
		, network::handshake_data hdata, data_server_context& context)
	: data_connection(context)
	, encrypted_connection(c, std::move(hdata), server)
	, context_(context)
	{}

	~data_server_client() {
		encrypted_connection::close();
	}

	void send(octet_span s) override {
		encrypted_connection::send(s);
	}

	void close() override {
		terminate(securepath::error());
	}

	void terminate(securepath::error const& err) {
		encrypted_connection::close();
		on_disconnected(err);
	}

	void on_connected() override {
		if(!remote_key_id()) {
			// RD12: no anonymous clients on the data listener
			LOG_WARN("no client key set on a data connection, closing...");
			terminate(make_error(protocol::errc::invalid_client_key));
		}
	}

	void on_disconnected(securepath::error const& error) override {
		LOG_TRACE("data client disconnected ({}): {}", remote_key_id().value_or(crypto::public_key_id{}), error);
		if(std::exchange(admitted_, false)) {
			context_.leave(*remote_key_id());
		}
	}

	void on_received(octet_span s) override {
		try {
			deser_.handle(s, std::ref(*this));
		} catch(error const& err) {
			LOG_WARN("error while handling data packet [err={}]", err);
			terminate(err);
		} catch(...) {
			LOG_WARN("unknown exception while handling data packet");
			terminate(make_error(protocol::errc::invalid_state));
		}
	}

	void operator()(protocol::data_hello const& p) {
		auto const key_id = remote_key_id();
		auto err = (key_id && !connection_good_) ? data_connection::on_connect(p, *key_id)
			: make_error(protocol::errc::invalid_state);
		if(!err && !context_.admit(*key_id)) {
			LOG_INFO("client {} has too many data connections open", *key_id);
			err = make_error(protocol::errc::invalid_state, "too many connections");
		}
		if(err) {
			LOG_INFO("data hello refused, closing connection...");
			terminate(err);
		} else {
			admitted_ = true;
			connection_good_ = true;
		}
	}

	template<typename T>
	void operator()(T const& p) {
		if(connection_good_) {
			this->handle(p);
		} else {
			LOG_WARN("data packets before data_hello received");
			terminate(make_error(protocol::errc::invalid_client_key));
		}
	}

private:
	// a chunk packet is up to chunk_size_range.highest and a manifest up to max_data_chunks digests:
	// the transport frame is the bound, not the deserialiser's 1 MiB default
	serialisation::packet_deserialiser<protocol::c2d_types> deser_{network::max_frame_size};
	data_server_context& context_;
	bool connection_good_{};
	bool admitted_{};
};

}

/// load signals of this data server (RD13)
struct holder_load_signals {
	std::uint64_t stored_bytes{};
	std::uint64_t uploads_in_progress{};
};

class data_server::impl
	: public network::encrypted_server
	, public data_server_context
{
public:
	impl(network::context& context, data_server_params params)
	: encrypted_server(context)
	, params_(std::move(params))
	, context_(context)
	, handshake_data_(network::handshake_tag::public_key)
	{}

	std::shared_ptr<network::encrypted_connection> create_connection() override {
		return std::make_shared<data_server_client>(context_, shared_from_this(), handshake_data_, *this);
	}

	/// the record servers whose tickets are accepted: the configured ones and this server itself
	void resolve_issuers() {
		std::set<crypto::public_key_id> issuers;
		for(auto const& server : params_.record_servers) {
			issuers.insert(server.key);
		}
		crypto::public_key_id own;
		if(auto key = context_.private_data().my_private_key()) {
			own = key->id();
			issuers.insert(own);
			// tickets an all-in-one server issues to itself verify with its own key
			if(!context_.public_keys().find(own)) {
				context_.public_keys().insert(key->public_key());
			}
		}
		std::unique_lock lock{mutex_};
		issuers_ = std::move(issuers);
		own_id_ = own;
	}

	// -- links to the record servers (RD13) --

	/// one configured record server: the link and its reconnect state
	struct link_state {
		link_state(asio::io_context& io, peer_config s) : server(std::move(s)), timer(io) {}

		peer_config server;
		std::shared_ptr<record_server_link> link;
		asio::steady_timer timer;
		std::chrono::seconds backoff{1};
	};

	void start_links() {
		for(auto const& server : params_.record_servers) {
			// the own entry of a shared cluster configuration: an all-in-one server hears
			// of its completions directly
			if(server.key != own_id_ && own_id_.is_valid() && !server.host.empty()) {
				links_.push_back(std::make_shared<link_state>(context_.io_context(), server));
				connect_link(links_.back());
			}
		}
	}

	/// what a link tells this server; everything holds the server and the link state weakly
	record_server_link::hooks link_hooks(std::shared_ptr<link_state> const& state) {
		record_server_link::hooks hooks;
		hooks.whole_view = [weak = weak_self()] {
			auto self = weak.lock();
			return self ? self->whole_view() : std::vector<protocol::announce_data>{};
		};
		hooks.trust = [weak = weak_self()](crypto::public_key const& key) {
			auto self = weak.lock();
			if(self && !self->context_.public_keys().find(key.id())) {
				LOG_INFO("trusting the key of record server {}", key.id());
				self->context_.public_keys().insert(key);
			}
		};
		hooks.release = [weak = weak_self()](protocol::storage_id const& sid, std::vector<data_id> const& ids) {
			auto self = weak.lock();
			if(self) {
				self->release(sid, ids);
			}
		};
		hooks.replicate = [weak = weak_self(), asked_by = state->server.key](protocol::storage_id const& sid
			, std::vector<data_descriptor> const& descriptors) {
			if(auto self = weak.lock()) {
				self->replicate(sid, descriptors, asked_by);
			}
		};
		hooks.connected = [wstate = std::weak_ptr<link_state>(state), weak = weak_self()] {
			auto self = weak.lock();
			auto st = wstate.lock();
			if(self && st) {
				std::unique_lock lock{self->mutex_};
				st->backoff = std::chrono::seconds{1};
			}
		};
		hooks.disconnected = [wstate = std::weak_ptr<link_state>(state), weak = weak_self()] {
			auto self = weak.lock();
			auto st = wstate.lock();
			if(self && st) {
				self->schedule_reconnect(st);
			}
		};
		return hooks;
	}

	void connect_link(std::shared_ptr<link_state> const& state) {
		auto link = std::make_shared<record_server_link>(context_, state->server, own_id_, link_hooks(state));
		{
			std::unique_lock lock{mutex_};
			if(closing_) {
				return;
			}
			state->link = link;
		}
		link->start(params_.timeout);
		// close_links may have closed it between the check and the start, and a start
		// after a close connects anew: nobody would ever close that one
		bool closing{};
		{
			std::unique_lock lock{mutex_};
			closing = closing_;
		}
		if(closing) {
			link->close();
		}
	}

	/// exponential backoff capped at one minute
	void schedule_reconnect(std::shared_ptr<link_state> const& state) {
		std::unique_lock lock{mutex_};
		if(!closing_) {
			state->timer.expires_after(state->backoff);
			state->backoff = std::min(state->backoff * 2, std::chrono::seconds{60});
			state->timer.async_wait([weak = weak_self(), wstate = std::weak_ptr<link_state>(state)](std::error_code const& ec) {
				auto self = weak.lock();
				auto st = wstate.lock();
				if(self && st && !ec) {
					self->connect_link(st);
				}
			});
		}
	}

	/// closed outside the mutex: closing waits for the link's strand, whose handlers take it
	void close_links() {
		std::vector<std::shared_ptr<link_state>> links;
		{
			std::unique_lock lock{mutex_};
			closing_ = true;
			links.swap(links_);
		}
		for(auto const& state : links) {
			state->timer.cancel();
			if(state->link) {
				state->link->close();
			}
		}
	}

	std::vector<std::shared_ptr<record_server_link>> live_links() const {
		std::unique_lock lock{mutex_};
		std::vector<std::shared_ptr<record_server_link>> ret;
		for(auto const& state : links_) {
			if(state->link) {
				ret.push_back(state->link);
			}
		}
		return ret;
	}

	std::shared_ptr<record_server_link> link_to(crypto::public_key_id const& record_server) const {
		std::unique_lock lock{mutex_};
		std::shared_ptr<record_server_link> ret;
		for(auto const& state : links_) {
			if(state->server.key == record_server && state->link) {
				ret = state->link;
			}
		}
		return ret;
	}

	// -- copies of data held elsewhere (RD8/RD13 replication) --

	void start_replicator() {
		data_replicator_hooks hooks;
		hooks.store = [weak = weak_self()](protocol::storage_id const& sid) {
			auto self = weak.lock();
			if(!self) {
				throw make_error(securepath::errc::invalid_state, "the data server is gone");
			}
			return self->acquire_store(sid);
		};
		hooks.ticket = [weak = weak_self()](protocol::storage_id const& sid, data_descriptor const& descriptor
			, std::move_only_function<void(util::result<data_grant>)> answer) {
			if(auto self = weak.lock()) {
				self->replica_ticket(sid, descriptor, std::move(answer));
			} else {
				answer(make_error(securepath::errc::invalid_state, "the data server is gone"));
			}
		};
		hooks.complete = [weak = weak_self()](protocol::storage_id const& sid, data_id const& id) {
			if(auto self = weak.lock()) {
				self->forget_asker(id);
				self->announce_complete(sid, id);
			}
		};
		hooks.now = [] { return clock_type::now(); };
		auto replicator = std::make_shared<data_replicator>(context_, std::move(hooks), params_.replication, params_.timeout);
		std::unique_lock lock{mutex_};
		replicator_ = std::move(replicator);
	}

	void stop_replicator() {
		std::shared_ptr<data_replicator> replicator;
		{
			std::unique_lock lock{mutex_};
			replicator.swap(replicator_);
			asked_by_.clear();
		}
		if(replicator) {
			replicator->close();
		}
	}

	/// asked_by: the record server that wants the copies, nullopt for the own record role
	std::size_t replicate(protocol::storage_id const& sid, std::vector<data_descriptor> const& descriptors
		, std::optional<crypto::public_key_id> const& asked_by) {
		std::shared_ptr<data_replicator> replicator;
		{
			std::unique_lock lock{mutex_};
			replicator = replicator_;
			for(auto const& descriptor : descriptors) {
				asked_by_[descriptor.manifest_digest] = asked_by;
			}
		}
		return replicator ? replicator->replicate(sid, descriptors) : 0;
	}

	void forget_asker(data_id const& id) {
		std::unique_lock lock{mutex_};
		asked_by_.erase(id);
	}

	/// the ticket of a pull comes from the record server that asked for the copy: it
	/// knows the data is committed and who holds it
	void replica_ticket(protocol::storage_id const& sid, data_descriptor const& descriptor
		, std::move_only_function<void(util::result<data_grant>)> answer) {
		bool known{};
		std::optional<crypto::public_key_id> asked_by;
		data_server::replica_ticket_source own;
		{
			std::unique_lock lock{mutex_};
			auto it = asked_by_.find(descriptor.manifest_digest);
			known = it != asked_by_.end();
			asked_by = known ? it->second : std::nullopt;
			own = own_tickets_;
		}
		auto const link = asked_by ? link_to(*asked_by) : nullptr;
		if(known && link) {
			link->request_ticket(sid, descriptor.manifest_digest, std::move(answer));
		} else if(known && !asked_by && own) {
			own(sid, descriptor, std::move(answer));
		} else {
			answer(make_error(securepath::errc::invalid_state, "nobody to ask for the ticket of the copy"));
		}
	}

	std::size_t pending_replications() const {
		std::unique_lock lock{mutex_};
		return replicator_ ? replicator_->pending() : 0;
	}

	std::vector<protocol::announce_data> whole_view() {
		return announcements(own_id_);
	}

	// -- data_server_context --

	std::shared_ptr<server_data_store> acquire_store(protocol::storage_id const& sid) override {
		if(sid.empty()) {
			throw make_error(protocol::errc::no_such_storage);
		}
		std::unique_lock lock{mutex_};
		auto it = stores_.find(sid);
		if(it == stores_.end()) {
			auto const dir = std::filesystem::path{params_.storage_root} / to_hex(sid);
			std::filesystem::create_directories(dir);
			LOG_TRACE("opening data store (sid={})", to_hex(sid));
			auto db = database::sqlite::create_sqlite_connection((dir / "data.db").string());
			it = stores_.emplace(sid, std::make_shared<server_data_store>(db, dir / "data", params_.quota, params_.transfer)).first;
		}
		return it->second;
	}

	crypto::public_key_access const& keys() const override {
		return context_.public_keys();
	}

	bool trusted_issuer(crypto::public_key_id const& id) const override {
		std::unique_lock lock{mutex_};
		return issuers_.contains(id);
	}

	void announce_complete(protocol::storage_id const& sid, data_id const& id) override {
		complete_handler handler;
		{
			std::unique_lock lock{mutex_};
			handler = on_complete_;
		}
		if(handler) {
			handler(sid, id);
		}
		// a separate data server tells its record servers
		auto const links = live_links();
		auto const news = links.empty() ? std::nullopt : announcement(own_id_, sid, id);
		if(news) {
			for(auto const& link : links) {
				link->announce(*news);
			}
		}
	}

	time_point now() const override {
		return clock_type::now();
	}

	bool admit(crypto::public_key_id const& key) override {
		std::unique_lock lock{mutex_};
		auto& sessions = sessions_[key];
		bool const room = sessions < params_.max_sessions_per_key;
		if(room) {
			++sessions;
		}
		return room;
	}

	void leave(crypto::public_key_id const& key) override {
		std::unique_lock lock{mutex_};
		auto it = sessions_.find(key);
		if(it != sessions_.end() && --it->second == 0) {
			sessions_.erase(it);
		}
	}

	// -- expiry of incomplete uploads --

	std::size_t expire_incomplete() {
		std::vector<std::shared_ptr<server_data_store>> stores;
		{
			std::unique_lock lock{mutex_};
			for(auto const& [sid, store] : stores_) {
				stores.push_back(store);
			}
		}
		std::size_t removed = 0;
		auto const untouched_since = now() - params_.incomplete_upload_expiry;
		for(auto const& store : stores) {
			removed += store->expire_incomplete(untouched_since);
		}
		return removed;
	}

	std::vector<std::pair<protocol::storage_id, std::shared_ptr<server_data_store>>> open_stores() const {
		std::unique_lock lock{mutex_};
		return {stores_.begin(), stores_.end()};
	}

	/// the stores found under the storage root are opened so their leftovers expire too
	void open_existing_stores() {
		std::error_code ec;
		for(auto const& entry : std::filesystem::directory_iterator(params_.storage_root, ec)) {
			auto const name = entry.path().filename().string();
			bool const is_store = entry.is_directory() && !name.empty()
				&& name.find_first_not_of("0123456789ABCDEFabcdef") == std::string::npos
				&& std::filesystem::exists(entry.path() / "data.db");
			if(is_store) {
				try {
					acquire_store(from_hex(name));
				} catch(std::exception const& ex) {
					LOG_WARN("cannot open data store {} at start: {}", name, ex.what());
				}
			}
		}
	}

	// -- what is held, for the record servers (RD13) --

	/// the store of a storage that has one open here; a lookup never creates one
	std::shared_ptr<server_data_store> find_store(protocol::storage_id const& sid) const {
		std::unique_lock lock{mutex_};
		auto const it = stores_.find(sid);
		return it != stores_.end() ? it->second : nullptr;
	}

	std::size_t release(protocol::storage_id const& sid, std::vector<data_id> const& ids) {
		auto const store = find_store(sid);
		std::size_t const released = store ? store->release(ids) : 0;
		if(released != 0) {
			LOG_INFO("released {} record data no record names any more (sid={})", released, to_hex(sid));
		}
		for(auto const& id : ids) {
			forget_asker(id);
		}
		return released;
	}

	std::optional<data_state_row> find(protocol::storage_id const& sid, data_id const& id) const {
		auto const store = find_store(sid);
		return store ? store->find(id) : std::nullopt;
	}

	std::vector<std::pair<protocol::storage_id, data_state_row>> complete_holdings() const {
		std::vector<std::pair<protocol::storage_id, data_state_row>> ret;
		for(auto const& [sid, store] : open_stores()) {
			for(auto& row : store->complete_data()) {
				ret.emplace_back(sid, std::move(row));
			}
		}
		return ret;
	}

	/// load signals (RD13): octets reserved by the known data, uploads in progress
	holder_load_signals load() const {
		holder_load_signals ret;
		for(auto const& [sid, store] : open_stores()) {
			ret.stored_bytes += store->used_bytes();
			ret.uploads_in_progress += store->uploads_in_progress();
		}
		return ret;
	}

	std::vector<protocol::announce_data> announcements(crypto::public_key_id const& holder) const {
		std::size_t const batch = 500;
		auto const signals = load();
		auto const uploads = static_cast<std::uint32_t>(signals.uploads_in_progress);
		std::vector<protocol::announce_data> ret;
		std::vector<protocol::data_holding_entry> entries;
		for(auto const& [sid, row] : complete_holdings()) {
			entries.push_back({sid, row.descriptor.manifest_digest, row.have.count(), row.have.size(), true});
			if(entries.size() == batch) {
				ret.emplace_back(holder, std::move(entries), signals.stored_bytes, uploads);
				entries.clear();
			}
		}
		if(!entries.empty() || ret.empty()) {
			ret.emplace_back(holder, std::move(entries), signals.stored_bytes, uploads);
		}
		// everything held: what the receiver knew of this holder before is replaced
		ret.front().view_begin = true;
		ret.back().view_end = true;
		return ret;
	}

	std::optional<protocol::announce_data> announcement(crypto::public_key_id const& holder
		, protocol::storage_id const& sid, data_id const& id) const {
		std::optional<protocol::announce_data> ret;
		auto const row = find(sid, id);
		if(row) {
			auto const signals = load();
			ret.emplace(holder, std::vector<protocol::data_holding_entry>{{sid, id, row->have.count(), row->have.size()
				, row->state == record_data_state::in_sync}}, signals.stored_bytes, static_cast<std::uint32_t>(signals.uploads_in_progress));
		}
		return ret;
	}

	std::weak_ptr<impl> weak_self() {
		return std::static_pointer_cast<impl>(shared_from_this());
	}

	void schedule_expiry() {
		std::unique_lock lock{mutex_};
		if(!closing_ && timer_) {
			timer_->expires_after(params_.expiry_check_interval);
			timer_->async_wait([weak = weak_self()](std::error_code const& ec) {
				auto self = weak.lock();
				if(self && !ec) {
					self->expire_incomplete();
					self->schedule_expiry();
				}
			});
		}
	}

	void start_expiry() {
		{
			std::unique_lock lock{mutex_};
			closing_ = false;
			timer_.emplace(context_.io_context());
		}
		schedule_expiry();
	}

	void stop_expiry() {
		std::unique_lock lock{mutex_};
		closing_ = true;
		if(timer_) {
			timer_->cancel();
		}
	}

public:
	mutable std::mutex mutex_;
	data_server_params params_;
	network::context& context_;
	network::handshake_data handshake_data_;
	std::map<protocol::storage_id, std::shared_ptr<server_data_store>> stores_;
	/// connections open per client key
	std::map<crypto::public_key_id, std::size_t> sessions_;
	std::set<crypto::public_key_id> issuers_;
	crypto::public_key_id own_id_;
	std::vector<std::shared_ptr<link_state>> links_;
	std::shared_ptr<data_replicator> replicator_;
	/// who asked for the copy of a data: a record server's key, nullopt for the own record role
	std::map<data_id, std::optional<crypto::public_key_id>> asked_by_;
	data_server::replica_ticket_source own_tickets_;
	complete_handler on_complete_;
	std::optional<asio::steady_timer> timer_;
	bool closing_{};
	std::atomic<bool> running_{false};
};

data_server::data_server(network::context& context, data_server_params params)
: impl_(std::make_shared<impl>(context, std::move(params)))
{
}

data_server::~data_server() {
	close();
}

void data_server::start() {
	impl_->resolve_issuers();
	impl_->open_existing_stores();
	impl_->expire_incomplete();
	impl_->start(impl_->params_.create_endpoint(), impl_->params_.timeout);
	impl_->running_ = true;
	impl_->start_expiry();
	impl_->start_replicator();
	impl_->start_links();
	LOG_INFO("data server listening on port {}", impl_->local_endpoint().port());
}

void data_server::close() {
	impl_->stop_replicator();
	impl_->close_links();
	impl_->stop_expiry();
	if(impl_->running_) {
		impl_->running_ = false;
		impl_->close();
	}
}

std::optional<asio::ip::tcp::endpoint> data_server::local_endpoint() const {
	std::optional<asio::ip::tcp::endpoint> ret;
	if(impl_->running_) {
		ret = impl_->local_endpoint();
	}
	return ret;
}

void data_server::set_complete_handler(complete_handler handler) {
	std::unique_lock lock{impl_->mutex_};
	impl_->on_complete_ = std::move(handler);
}

std::shared_ptr<server_data_store> data_server::open_store(protocol::storage_id const& sid) {
	return impl_->acquire_store(sid);
}

std::size_t data_server::expire_incomplete() {
	return impl_->expire_incomplete();
}

std::size_t data_server::release(protocol::storage_id const& sid, std::vector<data_id> const& ids) {
	return impl_->release(sid, ids);
}

std::optional<data_state_row> data_server::find(protocol::storage_id const& sid, data_id const& id) {
	return impl_->find(sid, id);
}

std::vector<std::pair<protocol::storage_id, data_state_row>> data_server::complete_holdings() {
	return impl_->complete_holdings();
}

std::vector<protocol::announce_data> data_server::announcements(crypto::public_key_id const& holder) {
	return impl_->announcements(holder);
}

std::optional<protocol::announce_data> data_server::announcement(crypto::public_key_id const& holder
	, protocol::storage_id const& sid, data_id const& id) {
	return impl_->announcement(holder, sid, id);
}

std::uint64_t data_server::stored_bytes() {
	return impl_->load().stored_bytes;
}

std::uint64_t data_server::uploads_in_progress() {
	return impl_->load().uploads_in_progress;
}

void data_server::set_replica_ticket_source(replica_ticket_source source) {
	std::unique_lock lock{impl_->mutex_};
	impl_->own_tickets_ = std::move(source);
}

std::size_t data_server::replicate(protocol::storage_id const& sid, std::vector<data_descriptor> const& descriptors) {
	return impl_->replicate(sid, descriptors, std::nullopt);
}

std::size_t data_server::pending_replications() const {
	return impl_->pending_replications();
}

std::vector<crypto::public_key_id> data_server::connected_record_servers() const {
	std::vector<crypto::public_key_id> ret;
	std::unique_lock lock{impl_->mutex_};
	for(auto const& state : impl_->links_) {
		if(state->link && state->link->ready()) {
			ret.push_back(state->server.key);
		}
	}
	return ret;
}

}
