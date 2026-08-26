#pragma once

#include <format>
#include <sstream>

namespace securepath::sync::util {

/**
 * std::formatter base that formats a type via its ostream operator<<.
 * Use through SPSYNC_FORMAT_VIA_OSTREAM(type) after the operator<< declaration.
 */
struct ostream_formatter {
	constexpr auto parse(std::format_parse_context& ctx) {
		return ctx.begin();
	}
	template<typename T, typename FormatContext>
	auto do_format(T const& v, FormatContext& ctx) const {
		std::ostringstream os;
		os << v;
		return std::format_to(ctx.out(), "{}", os.view());
	}
};

/// format any ostream-printable value to a string (for std types we may not specialise std::formatter for)
template<typename T>
std::string fmt_stream(T const& v) {
	std::ostringstream os;
	os << v;
	return os.str();
}

}

#define SPSYNC_FORMAT_VIA_OSTREAM(...) \
template<> struct std::formatter<__VA_ARGS__> : securepath::sync::util::ostream_formatter { \
	template<typename FormatContext> \
	auto format(__VA_ARGS__ const& v, FormatContext& ctx) const { return do_format(v, ctx); } \
};
