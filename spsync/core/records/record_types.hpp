#ifndef SPSYNC_CORE_RECORD_TYPES_HEADER
#define SPSYNC_CORE_RECORD_TYPES_HEADER

namespace securepath::sync {

/**
 * Types of the records
 */
enum record_type_tag {
	user_change_record_tag = 1,
	data_change_record_tag,
	segment_record_tag
};

}

#endif
