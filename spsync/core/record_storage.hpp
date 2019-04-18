#ifndef SPSYNC_CORE_RECORD_STORAGE_HEADER
#define SPSYNC_CORE_RECORD_STORAGE_HEADER

#include "record_interface.hpp"

#include <memory>

namespace securepath::sync {

/**
 * Keeps records and their current state which is used by the comm layer and the synchroniser
 *
 */
class record_storage {
public:
	record_storage();
	~record_storage();

	// overall record chain
	//record_handle find_last();

	// per object id operations
	//record_handle find_last(object_id);
	//record_handle find_first(object_id);
	//record_handle find(tag);

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif
