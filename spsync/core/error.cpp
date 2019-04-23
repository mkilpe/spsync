#include "error.hpp"

namespace securepath::sync {

namespace {
	int const start_value = static_cast<int>(errc::no_encryption_key_set);

	char const* errors[] =
		{ "no encryption key set"
		};

	static_assert(sizeof(errors)/sizeof(*errors)
		 == static_cast<int>(errc::end_of_list)-start_value, "wrong number of errors");

	error_category& err_cat() {
		static error_category cat;
		return cat;
	}
}

char const* spsync_category::name() const noexcept {
	return "spsync error";
}

std::error_condition spsync_category::default_error_condition(int ev) const noexcept {
	std::error_condition ret = std::error_condition(securepath::errc::unknown_error);
	if(ev >= start_value && ev < static_cast<int>(errc::end_of_list)) {
		ret = std::error_condition(static_cast<errc>(ev));
	}
	return ret;
}

bool spsync_category::equivalent(std::error_code const& code, int condition) const noexcept {
	return *this == code.category() && code.value() == condition;
}

std::string spsync_category::message(int ev) const {
	std::string ret = "unknown error";
	if(ev >= start_value && ev < static_cast<int>(errc::end_of_list)) {
		ret = errors[ev-start_value];
	}
	return ret;
}

std::error_condition make_error_condition(errc e) {
	return std::error_condition(static_cast<int>(e), err_cat());
}

std::error_code make_error_code(errc e) {
    return std::error_code(static_cast<int>(e), err_cat());
}

error make_error(errc e, std::string msg) {
	return error(make_error_code(e), std::move(msg));
}

}
