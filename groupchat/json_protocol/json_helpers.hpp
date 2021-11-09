
#pragma once
#include "json.hpp"

#include <groupchat/core/types.hpp>
#include <spsync/client/request.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/error.hpp>
#include <string_view>

namespace securepath::groupchat::json_protocol {

inline json::object error_to_object(securepath::error const& err) {
	return json::object{
			{"code", err.code().value()},
			{"message", err.code().message()},
			{"aux", err.message()}};
}

inline std::string error_to_json(securepath::error const& err) {
	json::object ret{{"error", error_to_object(err)}};
	LOG_TRACE("error = %", ret);
	return json::serialize(ret);
}

inline json::object server_to_object(host_port const& server) {
	return json::object{
			{"host", server.host},
			{"port", server.port}};
}

inline json::object contacting_to_object(sync::client::request const& req
	, std::string const& name
	, std::string const& message)
{
	return json::object{
		{"action", "contacting"},
		{"state", to_string(req.state)},
		{"requestid", req.id},
		{"sender", json::object
			{
				{"keyid", req.sender.id().public_key_id().in_hex()},
				{"name", name}
			}},
		{"message", message}};
}

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

inline std::string time_to_string(time_point time) {
	std::tm t{};
	if(!log::gmtime(time_point::clock::to_time_t(time), t)) {
		LOG_WARN("encode: cannot convert time");
		throw make_error(errc::invalid_data, "could not convert time");
	}
	char buffer[17] = {};
	std::snprintf(buffer, 16, "%04d%02d%02d%02d%02d%02dZ"
		, t.tm_year + 1900, t.tm_mon + 1, t.tm_mday
		, t.tm_hour, t.tm_min, t.tm_sec);
	return std::string(buffer);
}

}