#ifndef SPSYNC_CORE_RECORD_INTERFACE_HEADER
#define SPSYNC_CORE_RECORD_INTERFACE_HEADER

#include "types.hpp"

#include <memory>

namespace securepath::sync {

/**
 * Interface for stored records
 *
 * This interface is thread safe
 */
class record_interface {
public:
	virtual ~record_interface() = default;

	//get the record structure out
	//set/get the record state (pending commit, committed, ...?)
	//get data handle or alternatively read/write

	virtual record_tag tag() const = 0;
};

using record_handle = std::shared_ptr<record_interface>;

}

#endif
