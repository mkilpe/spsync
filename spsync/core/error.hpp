#pragma once

#include <securepath/util/error.hpp>

namespace securepath::sync {

enum class errc {
	no_encryption_key_set = 0x1000,
	no_encryption_key_found,
	invalid_record_chain_state,
	constraint_violation,
	invalid_record_state,
	not_authentic,
	invalid_configuration,
	/// the record would exceed the storage's max_record_size (checked before committing)
	record_too_big,
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

