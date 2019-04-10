#include "object_id.hpp"

#include <securepath/crypto/random.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::sync::util {

//Fixed size of the object id octets
std::size_t const object_id_size = 16;

object_id::object_id(octet_vector id)
: id_(std::move(id))
{
}

bool object_id::is_valid() const {
	return id_.size() == object_id_size;
}

octet_vector const& object_id::value() const {
	return id_;
}

std::string object_id::to_hex() const {
	return securepath::to_hex(id_);
}

object_id create_object_id() {
	return object_id{crypto::random_octet_vector(object_id_size)};
}

bool operator==(object_id const& left, object_id const& right) {
	return left.value() == right.value();
}

bool operator!=(object_id const& left, object_id const& right) {
	return !(left == right);
}

bool operator<(object_id const& left, object_id const& right) {
	return left.value() < right.value();
}

std::ostream& operator<<(std::ostream& out, object_id const& id) {
	return out << (id.is_valid() ? id.to_hex() : "<invalid object id>");
}

}