
#pragma once
#include "json.hpp"

#include <groupchat/core/types.hpp>
#include <spsync/client/request.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/error.hpp>
#include <string_view>

namespace securepath::groupchat::json_protocol {

json::object error_to_object(securepath::error const& err);
std::string error_to_json(securepath::error const& err);
json::object server_to_object(host_port const& server);

json::object contacting_to_object(sync::client::request const& req
	, std::string const& name
	, std::string const& message);

json::object invitation_to_object(sync::client::request const& req
	, sync::client::storage_info const& info
	, json::object const& sender
	, std::string const& name
	, std::string const& message);


inline std::string call(auto Func) {
	try {
		return Func();
	} catch(securepath::error const& err) {
		return error_to_json(err);
	} catch(std::exception const& exp) {
		return error_to_json(make_error(errc::exception_occurred, exp.what()));
	} catch(...) {
		return error_to_json(make_error(errc::exception_occurred, "Unknown exception"));
	}
}

template<class T>
T extract(json::object const& obj, std::string_view key) {
	auto it = obj.find(key);
	if(it == obj.end()) {
		throw make_error(errc::invalid_data, "missing element '" + std::string(key) + "'");
	}
	return json::value_to<T>(it->value());
}

template<class T>
std::optional<T> extract_opt(json::object const& obj, std::string_view key) {
	auto it = obj.find(key);
	return it != obj.end() ? json::value_to<T>(it->value()) : std::optional<T>{};
}

std::string time_to_string(time_point time);

}