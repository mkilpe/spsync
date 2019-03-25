#ifndef SPSYNC_CORE_DATA_CHANGE_HEADER_HEADER
#define SPSYNC_CORE_DATA_CHANGE_HEADER_HEADER

#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * This is the encrypted header in the data_change_record
 *
 */
class data_change_header {
public:

private:
	//hash of the changed data
	//hash of the previous state ?

	//arbitrary metadata for higher layers
};

}

#endif
