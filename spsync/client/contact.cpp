#include "contact.hpp"

namespace securepath::sync::client {

contact::contact(user_id id)
: id_(id)
{}

user_id contact::id() const {
	return id_;
}

std::string contact::name() const {
	auto v = find<std::string>("name");
	return v ? *v : id_.public_key_id().in_hex();
}

host_port contact::server() const {
	auto v = find<host_port>("server");
	return v ? *v : host_port{};
}

contact_state contact::state() const {
	auto v = find<int>("state");
	return v ? contact_state(*v) : contact_state::complete;
}

std::optional<octet_vector> contact::contacting_data() const {
	return find<octet_vector>("contacting_data");
}

void contact::set_name(std::string const& name) {
	insert("name", name);
}

void contact::set_server(host_port const& server) {
	insert("server", server);
}

void contact::set_state(contact_state state) {
	insert("state", int(state));
}

void contact::set_contacting_data(octet_vector const& data) {
	insert("contacting_data", data);
}

}
