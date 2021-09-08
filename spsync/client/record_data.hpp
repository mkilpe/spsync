#pragma once

#include <spsync/core/users.hpp>
#include <spsync/core/records/data_change_record.hpp>

namespace securepath::sync {

struct single_data_change {
	plain_single_change_data data;
	data_change_header header;
};

struct user_change {
	users members;
	util::metadata metadata;
};

}
