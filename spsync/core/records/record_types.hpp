#pragma once

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

