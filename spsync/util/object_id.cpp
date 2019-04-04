#include "object_id.hpp"

#include <securepath/crypto/random.hpp>

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

object_id create_object_id() {
	return object_id{crypto::random_octet_vector(object_id_size)};
}

}