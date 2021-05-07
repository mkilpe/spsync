#ifndef SPSYNC_PROTOCOL_ERROR_HEADER
#define SPSYNC_PROTOCOL_ERROR_HEADER

#include <securepath/util/error.hpp>

namespace securepath::sync::protocol {
inline namespace v1 {

enum class errc {
	no_such_storage = 1,
	record_already_committed,
	invalid_record,
	conflicting_record,
	record_out_of_sync,
	invalid_client_key,
	end_of_list
};

}

std::error_condition make_error_condition(errc e);
std::error_code make_error_code(errc e);

}

namespace std {

	template<>
	struct is_error_condition_enum<securepath::sync::protocol::errc>
		: public true_type {};
	template<>
	struct is_error_code_enum<securepath::sync::protocol::errc>
		: public true_type {};
}

#endif