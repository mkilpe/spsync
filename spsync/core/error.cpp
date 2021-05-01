#include "error.hpp"

namespace securepath::sync {

namespace {
	int const start_value = static_cast<int>(errc::no_encryption_key_set);

	char const* errors[] =
		{ "no encryption key set"
		, "invalid record chain state"
		, "constraint violation"
		};

	static_assert(sizeof(errors)/sizeof(*errors)
		 == static_cast<int>(errc::end_of_list)-start_value, "wrong number of errors");

	using category_type = error_category<errc, errc::no_encryption_key_set, errc::end_of_list>;

	category_type& err_cat() {
		static category_type cat("spsync error", errors);
		return cat;
	}
}

std::error_condition make_error_condition(errc e) {
	return std::error_condition(static_cast<int>(e), err_cat());
}

std::error_code make_error_code(errc e) {
    return std::error_code(static_cast<int>(e), err_cat());
}

}
