
#include "storage_server.hpp"

#include <flat_map>
#include "connection.hpp"
#include "data_release.hpp"
#include "data_server.hpp"
#include "peer_connection.hpp"
#include "storage.hpp"

#include <asio/steady_timer.hpp>

#include <spsync/protocol/error.hpp>
#include <spsync/protocol/server_protocol.hpp>

#include <securepath/crypto/private_data_access.hpp>
#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/network/encryption/framing.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

#include <algorithm>
#include <filesystem>

namespace securepath::sync {

asio::ip::tcp::endpoint storage_server_params::create_endpoint() const {
	return storage_server_endpoint.value_or(asio::ip::tcp::endpoint(asio::ip::address_v4::any(), storage_server_port));
}

asio::ip::tcp::endpoint storage_server_params::create_s2s_endpoint() const {
	return s2s_endpoint.value_or(asio::ip::tcp::endpoint(asio::ip::address_v4::any(), s2s_port));
}


class storage_server_client
	: public connection
	, public network::encrypted_connection
{
public:
	storage_server_client(
		network::context& c,
		std::shared_ptr<network::encrypted_server> server,
		network::handshake_data hdata,
		storage_server_context& context)
	: connection(context)
	, encrypted_connection(c, std::move(hdata), server)
	{
		LOG_TRACE("constructing storage_server_client {}", static_cast<void const*>(this));
	}

	~storage_server_client() {
		LOG_TRACE("destructing storage_server_client {}", static_cast<void const*>(this));
		encrypted_connection::close();
	}

	virtual void send(octet_span s) override {
		encrypted_connection::send(s);
	}

	virtual void close() override {
		terminate(securepath::error());
	}

	void terminate(securepath::error const& err) {
		encrypted_connection::close();
		on_disconnected(err);
	}

	virtual void on_connected() override {
		if(!remote_key_id()) {
			LOG_WARN("no client key set, closing connection...");
			terminate(make_error(protocol::errc::invalid_client_key));
		}
		// if key was set, we are waiting to receive client_hello next
	}

	virtual void on_disconnected(securepath::error const& error) override {
		LOG_TRACE("client disconnected ({}): {}", remote_key_id().value_or(crypto::public_key_id{}), error);
	}

	virtual void on_sent(std::size_t) override {

	}

	virtual void on_received(octet_span s) override {
		try {
			deser_.handle(s, std::ref(*this));
		} catch(error const& err) {
			LOG_WARN("error while handling packet [err={}]", err);
			terminate(err);
		} catch(...) {
			LOG_WARN("unknown exception while handling network packet");
			terminate(make_error(protocol::errc::invalid_state));
		}
	}

	void operator()(protocol::client_hello const& p) {
		LOG_INFO("client version: {}", p.version);
		auto key_id = remote_key_id();
		assert(key_id);
		if(connection_good_) {
			LOG_WARN("second client hello on a connected session ({})", *key_id);
			terminate(make_error(protocol::errc::invalid_state));
			return;
		}
		auto err = connection::on_connect(p, *key_id);
		if(err) {
			//on_connect failed, lets close, maybe client is too old version
			LOG_INFO("failed to connect, closing connection...");
			terminate(err);
		} else {
			//all good
			connection_good_ = true;
			LOG_TRACE("client connection successfully connected ({})", *key_id);
		}
	}

	template<typename T>
	void operator()(T const& p) {
		if(connection_good_) {
			this->handle(p);
		} else {
			LOG_WARN("packets before client_hello received");
			terminate(make_error(protocol::errc::invalid_client_key));
		}
	}

private:
	// a commit carries a record of up to max_record_size_range.highest: the transport frame is the
	// bound of a message, not the deserialiser's 1 MiB default
	serialisation::packet_deserialiser<protocol::c2s_types> deser_{network::max_frame_size};
	bool connection_good_{};
};

/// listener for incoming peer connections (plan 4.1); a separate acceptor so the client
/// and the s2s packet families stay apart
class s2s_listener : public network::encrypted_server {
public:
	s2s_listener(network::context& context, storage_server_context& sctx, network::handshake_data hdata)
	: encrypted_server(context)
	, sctx_(sctx)
	, hdata_(std::move(hdata))
	{}

	std::shared_ptr<network::encrypted_connection> create_connection() override {
		auto conn = std::make_shared<peer_connection>(context(), sctx_, hdata_, shared_from_this());
		{
			std::unique_lock lock{mutex_};
			std::erase_if(incoming_, [](auto const& w) { return w.expired(); });
			incoming_.push_back(conn);
		}
		return conn;
	}

	/// currently alive accepted peer connections
	std::vector<std::shared_ptr<peer_connection>> connections() const {
		std::unique_lock lock{mutex_};
		std::vector<std::shared_ptr<peer_connection>> ret;
		for(auto const& w : incoming_) {
			if(auto p = w.lock()) {
				ret.push_back(std::move(p));
			}
		}
		return ret;
	}

private:
	storage_server_context& sctx_;
	network::handshake_data hdata_;
	mutable std::mutex mutex_;
	std::vector<std::weak_ptr<peer_connection>> incoming_;
};

/// one configured peer: the outgoing connection and its reconnect state (plan 4.1)
struct peer_link {
	explicit peer_link(asio::io_context& io, peer_config p)
	: peer(std::move(p))
	, timer(io)
	{}

	peer_config peer;
	std::shared_ptr<peer_connection> conn;
	asio::steady_timer timer;
	std::chrono::seconds backoff{1};
};

namespace {

storage_config make_storage_config(storage_server_params const& p) {
	storage_config c{p.storage_root};
	c.set_default_limits(p.default_limits);
	return c;
}

}

class storage_server::impl
	: public network::encrypted_server
	, public storage_server_context
{
public:
	impl(network::context& context, storage_server_params params)
	: encrypted_server(context)
	, params_(std::move(params))
	, context_(context)
	, handshake_data_(network::handshake_tag::public_key)
	, default_storage_config_(make_storage_config(params_))
	, issuer_(params_.data_servers, availability_, params_.ticket_validity)
	{
		LOG_TRACE("constructing storage_server::impl {}", static_cast<void const*>(this));
	}

	~impl() {
		LOG_TRACE("destructing storage_server::impl {}", static_cast<void const*>(this));
	}

	virtual std::shared_ptr<network::encrypted_connection> create_connection() override {
		return std::make_shared<storage_server_client>(context_, shared_from_this(), handshake_data_, *this);
	}

	virtual void on_accept(std::shared_ptr<network::encrypted_connection> const&) override {

	}

	virtual std::shared_ptr<storage> acquire_sync(protocol::storage_id const& id, std::optional<storage_modes> create_modes) override {
		std::unique_lock lock{mutex_};
		auto it = storages_.find(id);
		if(it == storages_.end()) {
			LOG_TRACE("creating storage object (id={})", to_hex(id));
			std::shared_ptr<storage> p = std::make_shared<storage>(id, default_storage_config_, create_modes, &context_.public_keys(), &context_.private_data());
			p->set_data_release([weak = weak_self()](protocol::storage_id const& sid, std::vector<data_id> const& ids) {
					if(auto self = weak.lock()) {
						self->release_data(sid, ids);
					}
				});
			if(p->modes().replication != replication_mode::none) {
				p->set_peer_push([this](protocol::storage_id const& sid, storage_modes const& modes, block_envelope const& env) {
						push_to_peers(sid, modes, env);
					});
			}
			it = storages_.emplace(id, std::move(p)).first;
		} else if(create_modes && !modes_match(*create_modes, it->second->modes())) {
			throw make_error(protocol::errc::storage_mode_mismatch, "storage exists with different modes");
		}
		return it->second;
	}

	virtual void release_sync(std::shared_ptr<storage> storage) override {
		std::unique_lock lock{mutex_};
		// the map entry and this parameter are the only owners left
		if(storage.use_count() == 2) {
			LOG_TRACE("destroying storage object (id={})", to_hex(storage->id()));
			storages_.erase(storage->id());
			storage.reset();
		}
	}

	virtual std::shared_ptr<storage> find_open_sync(protocol::storage_id const& id) override {
		std::unique_lock lock{mutex_};
		auto it = storages_.find(id);
		return it != storages_.end() ? it->second : nullptr;
	}

	bool exists_on_disk(protocol::storage_id const& id) const {
		return std::filesystem::exists(default_storage_config_.storage_root_path() + "/" + to_hex(id) + "/storage.db");
	}

	virtual std::shared_ptr<storage> acquire_replica(protocol::storage_id const& id,
		std::optional<storage_modes> peer_modes) override
	{
		std::shared_ptr<storage> ret = find_open_sync(id);
		try {
			if(!ret && exists_on_disk(id)) {
				ret = acquire_sync(id, std::optional<storage_modes>{});
			} else if(!ret && peer_modes && peer_modes->replication != replication_mode::none
				&& valid_storage_modes(*peer_modes)) {
				LOG_INFO("creating the replica of storage {} with the modes a peer announced", to_hex(id));
				ret = acquire_sync(id, *peer_modes);
				// it answers clients storage_syncing until the peers' heads are covered (plan 5.2)
				ret->set_bootstrapping(true);
			}
		} catch(securepath::error const& err) {
			LOG_WARN("cannot open the replica of storage {}: {}", to_hex(id), err);
		}
		if(ret && (ret->modes().replication == replication_mode::none || (peer_modes && !modes_match(*peer_modes, ret->modes())))) {
			LOG_WARN("storage {} is not replicated here with the peer's modes", to_hex(id));
			ret = nullptr;
		}
		return ret;
	}

	/**
	 * Open every replicated storage found under the storage root (a restart, plan 5.1):
	 * only open storages announce heads, take pushes and serve pulls. Unreplicated ones
	 * are closed again right away.
	 */
	void open_replicated_storages() {
		std::error_code ec;
		auto const root = default_storage_config_.storage_root_path();
		for(auto const& entry : std::filesystem::directory_iterator(root, ec)) {
			auto const name = entry.path().filename().string();
			bool const looks_like_storage = entry.is_directory() && !name.empty()
				&& name.find_first_not_of("0123456789ABCDEFabcdef") == std::string::npos
				&& std::filesystem::exists(entry.path() / "storage.db");
			if(looks_like_storage) {
				try {
					auto handle = acquire_sync(from_hex(name), std::optional<storage_modes>{});
					if(handle->modes().replication == replication_mode::none) {
						release_sync(std::move(handle));
					} else {
						LOG_INFO("replicated storage {} opened at start", name);
					}
				} catch(std::exception const& ex) {
					LOG_WARN("cannot open storage {} at start: {}", name, ex.what());
				}
			}
		}
	}

	/// fan a committed envelope out to every authenticated peer (plan 4.2)
	void push_to_peers(protocol::storage_id const& sid, storage_modes const& modes, block_envelope const& env) {
		protocol::push_records packet{sid, {env}, modes};
		for(auto const& conn : peer_connections()) {
			conn->push(packet);
		}
	}

	/// resolve the configured identity against the actual server key (plan 3.3)
	void resolve_identity() {
		crypto::public_key_id actual;
		if(auto key = context_.private_data().my_private_key()) {
			actual = key->id();
		}
		std::unique_lock lock{mutex_};
		identity_ = resolve_server_identity(params_.server_id, params_.peers, actual);
		if(identity_.server_id.is_valid()) {
			LOG_INFO("storage server identity {} [{} peers]", identity_.server_id, identity_.peers.size());
		}
	}

	server_identity const& identity() const override {
		// only written during start(), stable afterwards
		return identity_;
	}

	void trust_peer_key(crypto::public_key const& key) override {
		if(!context_.public_keys().find(key.id())) {
			LOG_INFO("trusting the key of peer {}", key.id());
			context_.public_keys().insert(key);
		}
	}

	void learn_signer_key(crypto::public_key const& key) override {
		if(!key.verify_me()) {
			LOG_WARN("peer sent a public key that is not self authentic [id={}]", key.id());
		} else if(!context_.public_keys().find(key.id())) {
			LOG_INFO("learned the key of record signer {} from a peer", key.id());
			context_.public_keys().insert(key);
		}
	}

	std::optional<crypto::public_key> find_key(crypto::public_key_id const& id) const override {
		return context_.public_keys().find(id);
	}

	/// a connected peer announced a head of the storage we have not reached
	bool behind_a_peer(std::shared_ptr<storage> const& handle) {
		auto const& own = identity_.server_id;
		for(auto const& conn : peer_connections()) {
			for(auto const& head : conn->heads_of_peer(handle->id())) {
				if(head.origin != own && handle->known_origin_seq(head.origin) < head.block.sequence) {
					return true;
				}
			}
		}
		return false;
	}

	bool is_syncing(protocol::storage_id const& sid) override {
		auto handle = find_open_sync(sid);
		return handle && (handle->bootstrapping() || behind_a_peer(handle));
	}

	void note_caught_up(protocol::storage_id const& sid) override {
		auto handle = find_open_sync(sid);
		if(handle && handle->bootstrapping() && !behind_a_peer(handle)) {
			handle->set_bootstrapping(false);
		}
	}

	std::vector<protocol::storage_id> replicated_storages() const override {
		std::unique_lock lock{mutex_};
		std::vector<protocol::storage_id> ret;
		for(auto const& [sid, handle] : storages_) {
			if(handle->modes().replication != replication_mode::none) {
				ret.push_back(sid);
			}
		}
		return ret;
	}

	// -- record data (record_data.txt RD12/RD13) --

	util::result<issued_ticket> issue_data_ticket(storage const& st, data_id const& id,
		crypto::public_key_id const& member, std::uint32_t right) override {
		return issuer_.issue(st.id(), st.committed_data(id), member, right
			, context_.private_data().my_private_key(), clock_type::now());
	}

	std::vector<data_endpoint> data_endpoints() const override {
		return issuer_.data_servers();
	}

	void data_announced(protocol::announce_data const& p) override {
		LOG_TRACE("data announcement of holder {} [{} entries]", p.holder, p.entries.size());
		availability_.set_load(p.holder, holder_load{p.stored_bytes, p.uploads_in_progress});
		for(auto const& e : p.entries) {
			bool const news = availability_.announce(e.sid, e.data_id, data_holding{p.holder, e.have_chunks, e.total_chunks, e.complete});
			auto const handle = news ? find_open_sync(e.sid) : nullptr;
			if(handle) {
				// RD4: clients waiting for the data fetch without polling
				handle->notify_data(e.data_id, true);
			}
		}
	}

	bool is_data_server(crypto::public_key_id const& key) const override {
		auto const& servers = issuer_.data_servers();
		return key != identity_.server_id && std::ranges::find(servers, key, &data_endpoint::key) != servers.end();
	}

	/// a data server other than this server is configured: it will dial the s2s listener
	bool has_separate_data_servers() const {
		return std::ranges::any_of(issuer_.data_servers(), [this](data_endpoint const& e) { return e.key != identity_.server_id; });
	}

	std::vector<protocol::announce_data> own_data_announcements() override {
		std::vector<protocol::announce_data> ret;
		if(data_role_ && identity_.server_id.is_valid()) {
			ret = data_role_->announcements(identity_.server_id);
		}
		return ret;
	}

	/// the own data role completed a data: into the table here, and to the peers (RD13)
	void on_data_complete(protocol::storage_id const& sid, data_id const& id) {
		auto const announcement = identity_.server_id.is_valid()
			? data_role_->announcement(identity_.server_id, sid, id) : std::nullopt;
		if(announcement) {
			data_announced(*announcement);
			for(auto const& conn : peer_connections()) {
				conn->announce(*announcement);
			}
		}
	}

	/**
	 * No record of the storage names these data any more (RD9): nobody is sent to a
	 * holder for them again, the own data role drops them and the separate data servers
	 * are told over their links. A data server that is not connected now keeps its
	 * chunks: the release is not repeated (see record_data.txt RDS 9).
	 */
	void release_data(protocol::storage_id const& sid, std::vector<data_id> const& ids) {
		for(auto const& id : ids) {
			availability_.forget(sid, id);
		}
		if(data_role_) {
			data_role_->release(sid, ids);
		}
		auto const connections = peer_connections();
		for(auto const& packet : release_packets(sid, ids)) {
			for(auto const& conn : connections) {
				conn->release(packet);
			}
		}
	}

	void attach_data_role(data_server& role) {
		data_role_ = &role;
		role.set_complete_handler([weak = weak_self()](protocol::storage_id const& sid, data_id const& id) {
			if(auto self = weak.lock()) {
				self->on_data_complete(sid, id);
			}
		});
	}

	/// what the own data role held before this start goes into the table as well
	void announce_own_data() {
		for(auto const& announcement : own_data_announcements()) {
			data_announced(announcement);
		}
	}

	/// start the s2s side when peers are configured (plan 4.1)
	void start_s2s() {
		// peers exchange records over it, separate data servers announce what they hold
		if(identity_.peers.empty() && !(identity_.server_id.is_valid() && has_separate_data_servers())) {
			return;
		}
		s2s_ = std::make_shared<s2s_listener>(context_, *this, handshake_data_);
		s2s_->start(params_.create_s2s_endpoint(), params_.timeout);
		LOG_INFO("s2s listening on port {}", s2s_->local_endpoint().port());
		for(auto const& peer : identity_.peers) {
			links_.push_back(std::make_shared<peer_link>(context_.io_context(), peer));
			connect_link(links_.back());
		}
		ae_timer_.emplace(context_.io_context());
		schedule_anti_entropy();
	}

	/**
	 * The timer and link handlers run on io threads and may already be dequeued when
	 * close_s2s cancels them: they capture the impl and the link weakly and do nothing
	 * once either is gone (the storage_server destructor drops the impl right after close)
	 */
	std::weak_ptr<impl> weak_self() {
		return std::static_pointer_cast<impl>(shared_from_this());
	}

	/// the periodic heads announcement (plan 4.4); receivers pull what they are missing
	void schedule_anti_entropy() {
		std::unique_lock lock{mutex_};
		if(closing_ || !ae_timer_) {
			return;
		}
		ae_timer_->expires_after(params_.anti_entropy_interval);
		ae_timer_->async_wait([weak = weak_self()](std::error_code const& ec) {
			auto self = weak.lock();
			if(self && !ec) {
				self->run_anti_entropy();
			}
		});
	}

	void run_anti_entropy() {
		LOG_TRACE("anti-entropy tick");
		for(auto const& conn : peer_connections()) {
			conn->announce_heads();
		}
		schedule_anti_entropy();
	}

	void connect_link(std::shared_ptr<peer_link> const& link) {
		auto conn = std::make_shared<peer_connection>(context_, *this, handshake_data_);
		conn->set_disconnect_handler([weak = weak_self(), wlink = std::weak_ptr<peer_link>(link)](securepath::error const&) {
			auto self = weak.lock();
			auto l = wlink.lock();
			if(self && l) {
				self->schedule_reconnect(l);
			}
		});
		conn->set_connected_handler([weak = weak_self(), wlink = std::weak_ptr<peer_link>(link)] {
			// a link that came up starts over with the short backoff when it drops
			auto self = weak.lock();
			auto l = wlink.lock();
			if(self && l) {
				std::unique_lock lock{self->mutex_};
				l->backoff = std::chrono::seconds{1};
			}
		});
		{
			std::unique_lock lock{mutex_};
			if(closing_) {
				return;
			}
			link->conn = conn;
		}
		conn->connect_peer(link->peer, params_.timeout);
	}

	/// exponential backoff capped at one minute
	void schedule_reconnect(std::shared_ptr<peer_link> const& link) {
		std::unique_lock lock{mutex_};
		if(closing_) {
			return;
		}
		LOG_TRACE("reconnecting to peer {} in {}s", link->peer, link->backoff.count());
		link->timer.expires_after(link->backoff);
		link->backoff = std::min(link->backoff * 2, std::chrono::seconds{60});
		link->timer.async_wait([weak = weak_self(), wlink = std::weak_ptr<peer_link>(link)](std::error_code const& ec) {
			auto self = weak.lock();
			auto l = wlink.lock();
			if(self && l && !ec) {
				self->connect_link(l);
			}
		});
	}

	/**
	 * The connections are closed OUTSIDE the mutex: closing waits for the connection
	 * strand, which may be running the disconnect handler that takes the mutex (it sees
	 * closing_ and backs off). The links stay alive until every close returned.
	 */
	void close_s2s() {
		std::vector<std::shared_ptr<peer_link>> links;
		std::shared_ptr<s2s_listener> listener;
		{
			std::unique_lock lock{mutex_};
			closing_ = true;
			if(ae_timer_) {
				ae_timer_->cancel();
			}
			links.swap(links_);
			listener.swap(s2s_);
		}
		for(auto const& link : links) {
			link->timer.cancel();
			if(link->conn) {
				link->conn->close();
			}
		}
		if(listener) {
			listener->close();
		}
	}

	/// every live peer connection, outgoing and accepted
	std::vector<std::shared_ptr<peer_connection>> peer_connections() const {
		std::vector<std::shared_ptr<peer_connection>> ret;
		std::shared_ptr<s2s_listener> listener;
		{
			std::unique_lock lock{mutex_};
			for(auto const& link : links_) {
				if(link->conn) {
					ret.push_back(link->conn);
				}
			}
			listener = s2s_;
		}
		if(listener) {
			auto incoming = listener->connections();
			ret.insert(ret.end(), incoming.begin(), incoming.end());
		}
		return ret;
	}

public:
	mutable std::mutex mutex_;
	storage_server_params params_;
	network::context& context_;
	network::handshake_data handshake_data_;
	std::flat_map<protocol::storage_id, std::shared_ptr<storage>> storages_;
	storage_config default_storage_config_;
	server_identity identity_;

	// -- record data (record_data.txt RD12/RD13) --
	data_availability availability_;
	ticket_issuer issuer_;
	/// the data role of this server when it has one (all-in-one)
	data_server* data_role_{};

	// -- the s2s side (plan 4.1) --
	std::shared_ptr<s2s_listener> s2s_;
	/// shared so the timer and connection handlers can hold them weakly
	std::vector<std::shared_ptr<peer_link>> links_;
	std::optional<asio::steady_timer> ae_timer_;
	bool closing_{};
};


storage_server::storage_server(network::context& context, storage_server_params params)
: impl_(std::make_shared<impl>(context, params))
{
}

storage_server::~storage_server()
{
	LOG_TRACE("storage_server::~storage_server {}", static_cast<void const*>(impl_.get()));
	close();
}

void storage_server::start() {
	impl_->resolve_identity();
	impl_->start(impl_->params_.create_endpoint(), impl_->params_.timeout);
	if(!impl_->identity_.peers.empty()) {
		impl_->open_replicated_storages();
	}
	impl_->announce_own_data();
	impl_->start_s2s();
}

void storage_server::attach_data_role(data_server& role) {
	impl_->attach_data_role(role);
}

data_availability const& storage_server::availability() const {
	return impl_->availability_;
}

bool storage_server::has_storage(protocol::storage_id const& sid) const {
	return impl_->find_open_sync(sid) != nullptr || impl_->exists_on_disk(sid);
}

bool storage_server::is_syncing(protocol::storage_id const& sid) const {
	return impl_->is_syncing(sid);
}

bool storage_server::is_open(protocol::storage_id const& sid) const {
	return impl_->find_open_sync(sid) != nullptr;
}

void storage_server::close() {
	impl_->close_s2s();
	impl_->close();
}

server_identity storage_server::identity() const {
	std::unique_lock lock{impl_->mutex_};
	return impl_->identity_;
}

std::shared_ptr<storage> storage_server::open_storage(protocol::storage_id const& sid,
	std::optional<storage_modes> create_modes) {
	return impl_->acquire_sync(sid, create_modes);
}

std::optional<asio::ip::tcp::endpoint> storage_server::s2s_local_endpoint() const {
	std::optional<asio::ip::tcp::endpoint> ret;
	std::unique_lock lock{impl_->mutex_};
	if(impl_->s2s_) {
		ret = impl_->s2s_->local_endpoint();
	}
	return ret;
}

std::vector<crypto::public_key_id> storage_server::connected_peers() const {
	std::vector<crypto::public_key_id> ret;
	for(auto const& conn : impl_->peer_connections()) {
		if(auto id = conn->peer_id()) {
			ret.push_back(std::move(*id));
		}
	}
	return ret;
}

std::vector<origin_head> storage_server::heads_of_peer(crypto::public_key_id const& peer,
	protocol::storage_id const& sid) const {
	std::vector<origin_head> ret;
	for(auto const& conn : impl_->peer_connections()) {
		if(ret.empty() && conn->peer_id() == peer) {
			ret = conn->heads_of_peer(sid);
		}
	}
	return ret;
}

}

