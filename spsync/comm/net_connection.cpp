#include "net_connection.hpp"
#include "net_connection_impl.hpp"

#include <spsync/comm/comm.hpp>
#include <spsync/protocol/client_protocol.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/protocol/server_protocol.hpp>

#include <securepath/crypto/random.hpp>
#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/error.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/error.hpp>

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

void storage_connection::attach(comm_output& out) {
	static_cast<comm&>(input_).set_output(out);
	nconn_.attach(id_);
}

network_connection::network_connection(network::context& context, event_system::event_handler& handler)
: impl_(std::make_unique<network_connection_impl>(context, handler))
{
}

network_connection::~network_connection()
{
}

error network_connection::connect(std::string_view host, std::uint16_t port, std::chrono::seconds timeout) {
	error err;
	if(impl_->state() == network::encrypted_connection::not_connected) {
		impl_->connect(host, port, timeout);
	} else {
		LOG_TRACE("calling connect in some other than not_connected state");
		if(impl_->state() == network::encrypted_connection::connected) {
			err = make_error(network::errc::already_connected);
		} else {
			err = make_error(securepath::errc::invalid_state, "calling connect in some other than not_connected state");
		}
	}
	return err;
}

void network_connection::close() {
	impl_->close();
}

bool network_connection::is_connected() const {
	return impl_->state() == network::encrypted_connection::connected;
}

storage_id network_connection::create_storage(std::optional<storage_modes> modes) {
	storage_id id = crypto::random_octet_vector(16);
	impl_->send(protocol::create_storage{++impl_->call_id, id, to_wire(modes)});
	return id;
}

void network_connection::destroy_storage(storage_id const&) {
	assert(0 && "not implemented");
}

storage_connection network_connection::create_storage_connection(storage_id id, record_storage& storage, sync::progress& progress, std::optional<storage_modes> expected_modes
	, record_data_store* data, data_channel* channel, data_download_channel* download_channel) {
	auto p = std::make_unique<comm>(&*impl_, id, storage, progress, expected_modes, data, channel, download_channel);
	std::unique_lock lock{impl_->mutex};
	auto ret = impl_->comms.insert(std::make_pair(id, std::move(p)));
	if(!ret.second || impl_->attached_comms.count(id)) {
		LOG_WARN("already connection to storage ({})", to_hex(id));
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

network::context& network_connection::context() const {
	return impl_->context();
}

}
