#include "net_connection.hpp"

#include <spsync/comm/comm.hpp>
#include <spsync/protocol/client_protocol.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/protocol/server_protocol.hpp>

#include <securepath/crypto/random.hpp>
#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

storage_connection::storage_connection(storage_id id, network_connection_impl& nc, comm_input& ci)
: id_(std::move(id))
, nconn_(nc)
, input_(ci)
{
}

comm_input& storage_connection::input() const {
	return input_;
}

struct network_connection_impl : network::encrypted_connection {
	network_connection_impl(network::context& context, event_system::event_handler& handler)
	: encrypted_connection(context)
	, handler(handler)
	{}

	~network_connection_impl() {
		encrypted_connection::close();
	}

	template<typename T>
	void send(T const& p) {
		encrypted_connection::send(serialisation::asn_der_serialise_choice<protocol::c2s_types>(p));
	}

	void close(error const& err = {}) {
		LOG_TRACE("closing storage connection");
		encrypted_connection::close();
		on_disconnected(err);
	}

	void on_connected() override {
		LOG_TRACE("storage connection connected, sending client_hello...");
		deser.clear();
		send(protocol::client_hello{});
	}

	void on_disconnected(securepath::error const& error) override {
		LOG_INFO("storage connection disconnected: %", error);
		handler.emit<events::on_disconnect>(error);
	}

	void on_sent(std::size_t bytes) override {

	}

	void on_received(octet_span s) override {
		deser.handle(s,
			[this](auto const& packet) {
				this->handle(packet);
			});
	}

	void handle(protocol::server_hello const& p) {
		if(p.error) {
			LOG_WARN("server responded with error: %", p.error);
			close(protocol::to_error(p.error));
		} else {
			// notify higher level that we are connected now
			handler.emit<events::on_connect>();
		}
	}

	void handle(protocol::create_storage_reply const& p) {
		error err;
		if(p.error) {
			LOG_INFO("failed to create storage (%) on server: %", to_hex(p.sid), p.error);
			err = protocol::to_error(p.error);
		}
		handler.emit<events::on_create_storage>(p.sid, err);
	}

	void handle(protocol::destroy_storage_reply const& p) {

	}

	void handle(protocol::storage_management_reply const& p) {

	}

	template<typename Packet>
	void handle(Packet const& p) {
		std::unique_lock lock{mutex};
		auto it = attached_comms.find(p.sid);
		if(it != attached_comms.end()) {
			it->second->handle(p);
		}
	}

	void attach(storage_id const& id, comm_output& out) {
		std::unique_lock lock{mutex};
		auto node = comms.extract(id);
		if(node) {
			attached_comms.insert(std::move(node));
		}
	}
public:
	mutable std::mutex mutex;
	event_system::event_handler& handler;
	std::atomic<std::uint32_t> call_id{};
	serialisation::packet_deserialiser<protocol::s2c_types> deser;
	std::map<storage_id, std::unique_ptr<comm>> comms;
	std::map<storage_id, std::unique_ptr<comm>> attached_comms;
};

void storage_connection::attach(comm_output& out) {
	nconn_.attach(id_, out);
}

network_connection::network_connection(network::context& context, event_system::event_handler& handler)
: impl_(std::make_unique<network_connection_impl>(context, handler))
{
}

network_connection::~network_connection()
{
}

void network_connection::connect(std::string_view host, std::uint16_t port) {
	impl_->connect(host, port);
}

void network_connection::close() {
	impl_->close();
}

storage_id network_connection::create_storage() {
	storage_id id = crypto::random_octet_vector(16);
	impl_->send(protocol::create_storage{++impl_->call_id, id});
	return id;
}

void network_connection::destroy_storage(storage_id const&) {
	assert(0 && "not implemented");
}

storage_connection network_connection::create_storage_connection(storage_id id, record_storage& storage, sync::progress& progress) {
	auto p = std::make_unique<comm>(storage, progress);
	std::unique_lock lock{impl_->mutex};
	auto ret = impl_->comms.insert(std::make_pair(id, std::move(p)));
	if(!ret.second || impl_->attached_comms.count(id)) {
		LOG_WARN("already connection to storage (%)", to_hex(id));
		throw make_error(securepath::errc::invalid_state, "already connection to given storage");
	}
	return storage_connection(std::move(id), *impl_, *ret.first->second);
}

void network_connection::detach(storage_id const& id) {
	std::unique_lock lock{impl_->mutex};
	{
		auto it = impl_->attached_comms.find(id);
		if(it != impl_->attached_comms.end()) {
			impl_->attached_comms.erase(id);
		}
	}
	{
		auto it = impl_->comms.find(id);
		if(it != impl_->comms.end()) {
			impl_->comms.erase(id);
		}
	}
}

}
