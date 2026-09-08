
#include "user.hpp"

#include <sstream>
#include <securepath/serialisation/enum.hpp>

#include <cmath>
#include <format>
#include <ostream>

namespace securepath::sync::util {

user_id::user_id(crypto::public_key_id id)
: id_(std::move(id))
{
}

bool user_id::is_valid() const {
	return id_.is_valid();
}

crypto::public_key_id user_id::public_key_id() const {
	return id_;
}

bool operator==(user_id const& left, user_id const& right) {
	return left.public_key_id() == right.public_key_id();
}

bool operator<(user_id const& left, user_id const& right) {
	return left.public_key_id() < right.public_key_id();
}

std::string to_string(user_id const& id) {
	return std::format("{}", id.public_key_id());
}

std::ostream& operator<<(std::ostream& out, user_id const& id) {
	return out << to_string(id);
}

user::user(user_id id, host_port hp)
: id_(std::move(id))
, key_server_(std::move(hp))
{
}

bool user::is_valid() const {
	return id_.is_valid();
}

user_id user::id() const {
	return id_;
}

host_port user::key_server() const {
	return key_server_;
}

std::string to_string(user const& u) {
	return std::format("user={{{}, {}}}", u.id(), u.key_server());
}

std::ostream& operator<<(std::ostream& out, user const& u) {
	return out << to_string(u);
}

serialisation::serialiser& serialise(serialisation::serialiser& s, access_type const& v) {
	return securepath::serialisation::serialise(s, v);
}

serialisation::deserialiser& serialise(serialisation::deserialiser& s, access_type& v) {
	return securepath::serialisation::serialise(s, v);
}

std::string to_string(access_type const& access) {
	// the known bits by name, anything else (a hostile or newer record) as a number
	struct named { access_type bit; char const* name; };
	named const atomics[] = {
		{access_type::data_read_access, "read"},
		{access_type::data_write_access, "write"},
		{access_type::user_management_access, "management"}};
	std::ostringstream out;
	auto rest = static_cast<unsigned>(access);
	char const* sep = "";
	for(auto const& a : atomics) {
		if(rest & static_cast<unsigned>(a.bit)) {
			out << sep << a.name;
			sep = ", ";
			rest &= ~static_cast<unsigned>(a.bit);
		}
	}
	if(rest != 0) {
		out << sep << "unknown(0x" << std::hex << rest << ")";
		sep = ", ";
	}
	if(*sep == '\0') {
		out << "no access";
	}
	return out.str();
}

std::ostream& operator<<(std::ostream& out, access_type const& access) {
	return out << to_string(access);
}

bool operator==(user_access const& l, user_access const& r) {
	return l.user == r.user && l.access == r.access;
}

std::string to_string(user_access const& access) {
	return std::format("[{}: {}]", access.user, access.access);
}

std::ostream& operator<<(std::ostream& out, user_access const& access) {
	return out << to_string(access);
}

}