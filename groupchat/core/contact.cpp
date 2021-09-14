#include "contact.hpp"

namespace securepath::groupchat {

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

void contact::set_name(std::string const& name) {
	insert("name", name);
}

}
