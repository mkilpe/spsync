#include "connection.hpp"

#include <spsync/protocol/server_protocol.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

template<typename T>
void connection::send(T const& p) {
	send(serialisation::asn_der_serialise_choice<protocol::s2c_types>(p));
}

void connection::on_connect(crypto::public_key_id id) {
	id_ = std::move(id);
	send(protocol::server_hello{});
}

void connection::handle(protocol::create_storage const&) {

}

void connection::handle(protocol::destroy_storage const&) {

}

void connection::handle(protocol::storage_management const&) {

}

void connection::handle(protocol::request_sequence_number const&) {

}

void connection::handle(protocol::request_records const&) {

}

void connection::handle(protocol::request_data const&) {

}

void connection::handle(protocol::request_commit const&) {

}

}

