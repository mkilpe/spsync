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
	util::hash changed_data_hash_;
	//decide: hash of the previous state ?

	//arbitrary metadata for higher layers
	util::metadata metadata_;

};

}

#endif