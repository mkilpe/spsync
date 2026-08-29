#pragma once

#include <cstdint>

namespace securepath::sync {

/**
 * Types of the records
 */
enum record_type_tag : std::int64_t {
	user_change_record_tag = 1,
	data_change_record_tag,
	segment_record_tag
};

}

