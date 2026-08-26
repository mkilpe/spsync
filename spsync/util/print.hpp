#pragma once

#include <format>
#include <sstream>
#include <type_traits>
#include <string>
#include <string_view>

namespace securepath {

namespace detail {

template<typename T>
std::string print_arg(T const& v) {
	// not std::formattable: the securepath formatters hardcode std::format_context and
	// fail that concept; a specialisation exists iff the formatter is default-constructible
	if constexpr(std::is_default_constructible_v<std::formatter<T, char>>) {
		return std::format("{}", v);
	} else {
		std::ostringstream os;
		os << v;
		return os.str();
	}
}

inline void print_append(std::string& out, std::string_view msg) {
	out += msg;
}

template<typename Head, typename... Tail>
void print_append(std::string& out, std::string_view msg, Head const& head, Tail const&... tail) {
	auto pos = msg.find('%');
	if(pos == std::string_view::npos) {
		out += msg;
	} else {
		out += msg.substr(0, pos);
		out += print_arg(head);
		print_append(out, msg.substr(pos+1), tail...);
	}
}

}

/**
 * Old-style string building: each '%' in msg is replaced by the next argument.
 * Kept for the cli client and json test templates where std::format would need
 * every literal brace escaped; new code should use std::format directly.
 */
template<typename... Params>
std::string print(std::string_view msg, Params const&... params) {
	std::string out;
	out.reserve(msg.size());
	detail::print_append(out, msg, params...);
	return out;
}

}
