
#include "user.hpp"
#include <securepath/serialisation/enum.hpp>

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

serialisation::serialiser& serialise(serialisation::serialiser& s, access_type const& v) {
	return securepath::serialisation::serialise(s, v);
}

serialisation::deserialiser& serialise(serialisation::deserialiser& s, access_type& v) {
	return securepath::serialisation::serialise(s, v);
}

}