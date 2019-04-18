#ifndef SPSYNC_CORE_RECORD_INTERFACE_HEADER
#define SPSYNC_CORE_RECORD_INTERFACE_HEADER

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
};

using record_handle = std::shared_ptr<record_interface>;

}

#endif
