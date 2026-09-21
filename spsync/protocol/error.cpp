#include "error.hpp"
#include "protocol_base.hpp"

#include <securepath/log/log.hpp>

#include <charconv>
#include <string>
#include <string_view>

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
		, "invalid storage modes"
		, "storage syncing"
		, "record too big"
		, "invalid data ticket"
		, "data ticket expired"
		, "invalid data manifest"
		, "invalid data chunk"
		, "no such upload"
		, "data quota exceeded"
		, "data too big"
		, "unknown data"
		, "no data servers"
		, "data not held"
		, "data transfer quota exceeded"
		, "data pruned by the retention policy"
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

namespace {
	std::string_view const retry_prefix{"retry after "};
}

error make_retry_error(errc e, std::uint32_t retry_after_seconds) {
	return make_error(e, std::string{retry_prefix} + std::to_string(retry_after_seconds));
}

std::optional<std::chrono::seconds> retry_after(error const& err) {
	std::optional<std::chrono::seconds> ret;
	auto const msg = err.message();
	if(err.code().category() == error_category() && msg.starts_with(retry_prefix)) {
		std::uint32_t seconds = 0;
		auto const* first = msg.data() + retry_prefix.size();
		auto const* last = msg.data() + msg.size();
		auto const parsed = std::from_chars(first, last, seconds);
		if(parsed.ec == std::errc{} && parsed.ptr == last) {
			ret = std::chrono::seconds{seconds};
		}
	}
	return ret;
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
