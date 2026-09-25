// SPDX-License-Identifier: MIT

#include "json_helpers.hpp"

namespace securepath::groupchat::json_protocol {

json::object error_to_object(securepath::error const& err) {
	return json::object{
			{"code", err.code().value()},
			{"message", err.code().message()},
			{"aux", err.message()}};
}

std::string error_to_json(securepath::error const& err) {
	json::object ret{{"error", error_to_object(err)}};
	LOG_TRACE("error = {}", json::serialize(ret));
	return json::serialize(ret);
}

json::object server_to_object(host_port const& server) {
	return json::object{
			{"host", server.host},
			{"port", server.port}};
}

json::object contacting_to_object(sync::client::request const& req
	, std::string_view name
	, std::string_view message)
{
	return json::object{
		{"action", "contacting"},
		{"state", to_string(req.state)},
		{"requestid", req.id},
		{"sender", json::object
			{
				{"id", req.sender.id().public_key_id().in_hex()},
				{"name", name}
			}},
		{"message", message}};
}

json::object invitation_to_object(sync::client::request const& req
	, sync::client::storage_info const& info
	, json::object const& sender
	, std::string_view name
	, std::string_view message)
{
	return json::object{
		{"action", "invitation"},
		{"state", to_string(req.state)},
		{"requestid", req.id},
		{"sender", sender},
		{"message", message},
		{"storage", json::object
			{
				{"server", server_to_object(info.sync_server)},
				{"sid", to_hex(info.sid)},
				{"name", name}
			}
		}};
}

std::string time_to_string(time_point time) {
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