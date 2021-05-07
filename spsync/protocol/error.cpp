#include "error.hpp"

namespace securepath::sync::protocol {

namespace {
	char const* errors[] =
		{ "no such storage"
		, "record already committed"
		, "invalid record"
		, "conflicting record"
		, "record out of sync"
		, "invalid client key"
		};

	using category_type = error_category<errc, errc::no_such_storage, errc::end_of_list>;

	category_type& err_cat() {
		static category_type cat("spsync protocol error", errors);
		return cat;
	}
}

std::error_condition make_error_condition(errc e) {
	return err_cat().make_error_condition(e);
}

std::error_code make_error_code(errc e) {
	return err_cat().make_error_code(e);
}

}
