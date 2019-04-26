#include "record_storage.hpp"

namespace securepath::sync {

class record_storage::impl {

};

record_storage::record_storage()
: impl_(std::make_unique<impl>())
{
}

record_storage::~record_storage()
{
}

record_handle record_storage::find_last() const {
	return nullptr;
}

record_handle record_storage::find_last(object_id const&) const {
	return nullptr;
}

}
