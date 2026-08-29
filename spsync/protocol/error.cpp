#include "error.hpp"
#include "protocol_base.hpp"

#include <securepath/log/log.hpp>

namespace securepath::sync::protocol {

namespace {
	char const* errors[] =
		{ "no such storage"
		, "record already committed"
		, "invalid record"
		, "conflicting record"
		, "record out of sync"
		, "invalid client key"
		, "invalid state"
		, "storage mode mismatch"
		, "unknown signer"
		};

	using category_type = def_error_category<errc>;

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

std::error_category const& error_category() {
	return err_cat();
}

error to_error(network::net_error const& err) {
	error ret;
	if(err) {
		// todo: better handling of error translation
		if(err.category() == protocol::error_category().name()) {
			if(err.code() > int(protocol::errc::no_error) && err.code() < int(protocol::errc::end_of_list)) {
				ret = make_error(protocol::errc(err.code()), err.aux_message());
			}
		}
		if(!ret) {
			LOG_WARN("unknown error code from server: {}", err);
			ret = make_error(securepath::errc::unknown_error);
		}
	}
	return ret;
}


}
