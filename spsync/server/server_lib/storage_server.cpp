
#include "storage_server.hpp"
#include "connection.hpp"
#include "storage.hpp"

#include <spsync/protocol/error.hpp>
#include <spsync/protocol/server_protocol.hpp>

#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

asio::ip::tcp::endpoint storage_server_params::create_endpoint() const {
	return storage_server_endpoint.value_or(asio::ip::tcp::endpoint(asio::ip::address_v4::any(), storage_server_port));
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
		LOG_TRACE("constructing storage_server_client %", this);
	}

	~storage_server_client() {
		LOG_TRACE("destructing storage_server_client %", this);
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
		LOG_TRACE("client disconnected (%): %", remote_key_id().value_or(crypto::public_key_id{}), error);
	}

	virtual void on_sent(std::size_t) override {

	}

	virtual void on_received(octet_span s) override {
		try {
			deser_.handle(s, std::ref(*this));
		} catch(error const& err) {
			LOG_WARN("error while handling packet [err=%]", err);
			terminate(err);
		} catch(...) {
			LOG_WARN("unknown exception while handling network packet");
			terminate(make_error(protocol::errc::invalid_state));
		}
	}

	void operator()(protocol::client_hello const& p) {
		LOG_INFO("client version: %", p.version);
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
			LOG_TRACE("client connection successfully connected (%)", *key_id);
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
	{
		LOG_TRACE("constructing storage_server::impl %", this);
	}

	~impl() {
		LOG_TRACE("destructing storage_server::impl %", this);
	}

	virtual std::shared_ptr<network::encrypted_connection> create_connection() override {
		return std::make_shared<storage_server_client>(context_, shared_from_this(), handshake_data_, *this);
	}

	virtual void on_accept(std::shared_ptr<network::encrypted_connection> const&) override {

	}

	virtual std::shared_ptr<storage> acquire_sync(protocol::storage_id const& id) override {
		std::unique_lock lock{mutex_};
		auto it = storages_.find(id);
		if(it == storages_.end()) {
			LOG_TRACE("creating storage object (id=%)", to_hex(id));
			std::shared_ptr<storage> p = std::make_shared<storage>(id, default_storage_config_);
			it = storages_.emplace(id, std::move(p)).first;
		}
		return it->second;
	}

	virtual void release_sync(std::shared_ptr<storage> storage) override {
		std::unique_lock lock{mutex_};
		if(storage.use_count() == 1) {
			LOG_TRACE("destroying storage object (id=%)", to_hex(storage->id()));
			storages_.erase(storage->id());
			storage.reset();
		}
	}

public:
	mutable std::mutex mutex_;
	storage_server_params params_;
	network::context& context_;
	network::handshake_data handshake_data_;
	std::map<protocol::storage_id, std::shared_ptr<storage>> storages_;
	storage_config default_storage_config_;
};


storage_server::storage_server(network::context& context, storage_server_params params)
: impl_(std::make_shared<impl>(context, params))
{
}

storage_server::~storage_server()
{
	LOG_TRACE("storage_server::~storage_server %", impl_.get());
	close();
}

void storage_server::start() {
	impl_->start(impl_->params_.create_endpoint());
}

void storage_server::close() {
	impl_->close();
}

}

