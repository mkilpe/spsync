#ifndef SPSYNC_CORE_ERROR_HEADER
#define SPSYNC_CORE_ERROR_HEADER

#include <securepath/util/error.hpp>

namespace securepath::sync {

enum class errc {
	no_encryption_key_set = 0x1000,
	invalid_record_chain_state,
	constraint_violation,
	end_of_list
};

std::error_condition make_error_condition(errc e);
std::error_code make_error_code(errc e);

}

namespace std {

	template<>
	struct is_error_condition_enum<securepath::sync::errc>
		: public true_type {};
	template<>
	struct is_error_code_enum<securepath::sync::errc>
		: public true_type {};

}

#endif