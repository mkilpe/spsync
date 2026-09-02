
#include "storage_server.hpp"

#include <flat_map>
#include "connection.hpp"
#include "peer_connection.hpp"
#include "storage.hpp"

#include <asio/steady_timer.hpp>

#include <spsync/protocol/error.hpp>
#include <spsync/protocol/server_protocol.hpp>

#include <securepath/crypto/private_data_access.hpp>
#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/serialisation/util.hpp>

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
	serialisation::packet_deserialiser<protocol::c2s_types> deser_;
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
	, default_storage_config_(params_.storage_root)
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
			it = storages_.emplace(id, std::move(p)).first;
		} else if(create_modes && it->second->modes() != *create_modes) {
			throw make_error(protocol::errc::storage_mode_mismatch, "storage exists with different modes");
		}
		return it->second;
	}

	virtual void release_sync(std::shared_ptr<storage> storage) override {
		std::unique_lock lock{mutex_};
		if(storage.use_count() == 1) {
			LOG_TRACE("destroying storage object (id={})", to_hex(storage->id()));
			storages_.erase(storage->id());
			storage.reset();
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

	/// start the s2s side when peers are configured (plan 4.1)
	void start_s2s() {
		if(identity_.peers.empty()) {
			return;
		}
		s2s_ = std::make_shared<s2s_listener>(context_, *this, handshake_data_);
		s2s_->start(params_.create_s2s_endpoint(), params_.timeout);
		LOG_INFO("s2s listening on port {}", s2s_->local_endpoint().port());
		for(auto const& peer : identity_.peers) {
			links_.push_back(std::make_unique<peer_link>(context_.io_context(), peer));
			connect_link(*links_.back());
		}
	}

	void connect_link(peer_link& link) {
		auto conn = std::make_shared<peer_connection>(context_, *this, handshake_data_);
		conn->set_disconnect_handler([this, &link](securepath::error const&) {
			schedule_reconnect(link);
		});
		{
			std::unique_lock lock{mutex_};
			if(closing_) {
				return;
			}
			link.conn = conn;
		}
		conn->connect_peer(link.peer, params_.timeout);
	}

	/// exponential backoff capped at one minute; the links live as long as the impl
	void schedule_reconnect(peer_link& link) {
		std::unique_lock lock{mutex_};
		if(closing_) {
			return;
		}
		LOG_TRACE("reconnecting to peer {} in {}s", link.peer, link.backoff.count());
		link.timer.expires_after(link.backoff);
		link.backoff = std::min(link.backoff * 2, std::chrono::seconds{60});
		link.timer.async_wait([this, &link](std::error_code const& ec) {
			if(!ec) {
				connect_link(link);
			}
		});
	}

	/**
	 * The connections are closed OUTSIDE the mutex: closing waits for the connection
	 * strand, which may be running the disconnect handler that takes the mutex (it sees
	 * closing_ and backs off). The links stay alive until every close returned.
	 */
	void close_s2s() {
		std::vector<std::unique_ptr<peer_link>> links;
		std::shared_ptr<s2s_listener> listener;
		{
			std::unique_lock lock{mutex_};
			closing_ = true;
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

	// -- the s2s side (plan 4.1) --
	std::shared_ptr<s2s_listener> s2s_;
	std::vector<std::unique_ptr<peer_link>> links_;
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
	impl_->start_s2s();
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

