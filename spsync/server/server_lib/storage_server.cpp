
#include "storage_server.hpp"
#include "connection.hpp"
#include "storage.hpp"

#include <spsync/protocol/server_protocol.hpp>

#include <securepath/network/encryption/encrypted_server.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

asio::ip::tcp::endpoint storage_server_params::create_storage_server_endpoint() const {
	return storage_server_endpoint.value_or(asio::ip::tcp::endpoint(asio::ip::address_v4::any(), storage_server_port));
}


class storage_server_client
: public std::enable_shared_from_this<storage_server_client>
, public network::encrypted_connection
, public connection
{
public:
	storage_server_client(
		network::context& c,
		std::shared_ptr<network::encrypted_server> server,
		network::handshake_data hdata)
	: encrypted_connection(c, std::move(hdata), server)
	{
		LOG_TRACE("constructing storage_server_client %", this);
	}

	~storage_server_client() {
		LOG_TRACE("destructing storage_server_client %", this);
	}

	virtual void send(octet_span s) override {
		encrypted_connection::send(s);
	}

	virtual void close() override {
		encrypted_connection::close();
		on_disconnected(securepath::error());
	}

	virtual void on_connected() override {
		auto key_id = remote_key_id();
		if(key_id) {
			connection::on_connect(*key_id);
		} else {
			LOG_WARN("no client key set, closing connection...");
			close();
		}
	}

	virtual void on_disconnected(securepath::error const& error) override {
		LOG_TRACE("client disconnected (%): %", remote_key_id().value_or(crypto::public_key_id{}), error);
	}

	virtual void on_sent(std::size_t) override {

	}

	virtual void on_received(octet_span s) override {
		deser_.handle(s, std::ref(*this));
	}

	void operator()(protocol::client_hello const& p) {
		LOG_INFO("client version: %", p.version);
		//t: check the version et al
		connection_good_ = true;
	}

	template<typename T>
	void operator()(T const& p) {
		if(connection_good_) {
			this->handle(p);
		} else {
			LOG_WARN("packets before client_hello received");
		}
	}

private:
	serialisation::packet_deserialiser<protocol::c2s_types> deser_;
	bool connection_good_{};
};

class storage_server::impl
	: public network::encrypted_server
{
public:
	impl(network::context context, storage_server_params params)
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
		return std::make_shared<storage_server_client>(context_, shared_from_this(), handshake_data_);
	}

	virtual void on_accept(std::shared_ptr<network::encrypted_connection> const&) override {

	}

	std::shared_ptr<storage> acquire_sync(protocol::storage_id const& id) {
		std::unique_lock lock{mutex_};
		return nullptr;
	}

	void release_sync(std::shared_ptr<storage> storage) {
		std::unique_lock lock{mutex_};

	}

public:
	mutable std::mutex mutex_;
	storage_server_params params_;
	network::context& context_;
	network::handshake_data handshake_data_;
	std::map<protocol::storage_id, std::shared_ptr<storage>> storages_;
};


storage_server::storage_server(network::context context, storage_server_params params)
: impl_(std::make_unique<impl>(context, params))
{
}

storage_server::~storage_server()
{
	LOG_TRACE("storage_server::~storage_server %", impl_.get());
	close();
}

void storage_server::close() {
	impl_->close();
}

}
