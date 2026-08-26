
#include "user.hpp"
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

bool operator!=(user_id const& left, user_id const& right) {
	return !(left == right);
}

bool operator<(user_id const& left, user_id const& right) {
	return left.public_key_id() < right.public_key_id();
}

std::ostream& operator<<(std::ostream& out, user_id const& id) {
	return out << id.public_key_id();
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

std::ostream& operator<<(std::ostream& out, user const& u) {
	return out << "user={" << u.id() << ", " << std::format("{}", u.key_server()) << "}";
}

serialisation::serialiser& serialise(serialisation::serialiser& s, access_type const& v) {
	return securepath::serialisation::serialise(s, v);
}

serialisation::deserialiser& serialise(serialisation::deserialiser& s, access_type& v) {
	return securepath::serialisation::serialise(s, v);
}

std::ostream& operator<<(std::ostream& out, access_type const& access) {
	char const* const atomics[] = {"read", "write", "management"};
	int acc = static_cast<int>(access);
	bool first = true;

	if(access == access_type::no_access) {
		out << "no access";
	} else {
		do {
			int log = std::log2(acc);
			if(first) {
				first = false;
			} else {
				out << ", ";
			}
			out << atomics[log];
			acc -= std::exp2(log);
		} while(acc);
	}

	return out;
}

bool operator==(user_access const& l, user_access const& r) {
	return l.user == r.user && l.access == r.access;
}

bool operator!=(user_access const& l, user_access const& r) {
	return !(l == r);
}

std::ostream& operator<<(std::ostream& out, user_access const& access) {
	return out << "[" << access.user << ": " << access.access << "]";
}

}