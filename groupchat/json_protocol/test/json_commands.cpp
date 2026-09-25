// SPDX-License-Identifier: MIT

#include "json_commands.hpp"
#include <spsync/util/print.hpp>

#include <securepath/util/print_util.hpp>

namespace securepath::groupchat::json_protocol::test {

std::string json_get_account_result(std::string name) {
	return print(R"({ "user" : { "name": "%" } })", name);
}

std::string json_create_account(std::string name) {
	return print(R"({ "name": "%", "server": { "host": "127.0.0.1"} })", name);
}

std::string json_create_account_result(std::string name) {
	return print(R"({ "user" : { "name": "%" }, "server": { "host": "127.0.0.1"} })", name);
}

std::string json_get_contacts_result(std::vector<json_contact> list) {
	std::string res = R"({ "data" : [)";
	bool first = true;
	for(auto e : list) {
		if(!first) {
			res += ", ";
		}
		first = false;
		res += json_add_contact_result(e);
	}
	res += R"(]})";
	return res;
}

std::string json_add_contact(json_contact c, std::string message) {
	if(message.empty()) {
		return print(R"({ "name" : "%", "id": "%"})", c.name, c.kid.in_hex());
	} else {
		return print(R"({ "name" : "%", "id": "%", "message": "%"})", c.name, c.kid.in_hex(), message);
	}
}

std::string json_add_contact_result(json_contact c) {
	auto kid_str = c.kid.in_hex();
	return print(R"({ "name" : "%", "id": "%"})", c.name, kid_str);
}

std::string json_get_chats_result(std::vector<json_chat> list) {
	std::string res = R"({ "data" : [)";
	bool first = true;
	for(auto e : list) {
		if(!first) {
			res += ", ";
		}
		first = false;
		res += print(R"({"name": "%", "id": "%", "messages": [)", e.name, e.id);
		bool m_first = true;
		for(auto m : e.messages) {
			if(!m_first) {
				res += ", ";
			}
			m_first = false;
			res += json_message_to_string(m);
		}
		res += "]}";
	}
	res += R"(]})";
	return res;
}

std::string json_create_chat(std::string name, std::vector<crypto::public_key_id> list) {
	std::string res = print(R"({ "name": "%", "members" : [)", name);
	bool first = true;
	for(auto e : list) {
		if(!first) {
			res += ", ";
		}
		first = false;
		res += print(R"({"user": "%"})", e.in_hex());
	}
	res += R"(]})";
	return res;
}

json_create_chat_result::json_create_chat_result(std::string str)
{
	CHECK_NOTHROW([&]{
		auto obj = json::parse(str).as_object();
		result.name = extract<std::string>(obj, "name");
		result.id = extract<std::string>(obj, "id");
	}());
}

std::vector<json_chat> list_chats(std::string str) {
	std::vector<json_chat> res;
	CAPTURE(str);
	CHECK_NOTHROW([&]{
		auto obj = json::parse(str).as_object();
		auto arr = extract<json::array>(obj, "data");
		for(auto const& v : arr) {
			auto obj = v.as_object();
			res.push_back(json_chat{
				extract<std::string>(obj, "name"),
				extract<std::string>(obj, "id")});
			auto msgs = extract<json::array>(obj, "messages");
			res.back().messages = list_plain_messages(msgs);
		}
	}());
	return res;
}

std::string json_get_chat_members_result(std::vector<json_chat_member> list) {
	std::string res = R"({ "data" : [)";
	bool first = true;
	for(auto e : list) {
		if(!first) {
			res += ", ";
		}
		first = false;
		res += print(R"({"name": "%", "id": "%", "contact" : %})", e.name, e.kid.in_hex(), e.is_contact ? "true" : "false");
	}
	res += R"(]})";
	return res;
}

std::string json_get_chat_members(std::string id) {
	return print(R"({ "id" : "%"})", id);
}

std::string json_join_chat(std::string id) {
	return print(R"({ "id" : "%"})", id);
}

std::string json_join_chat_result(std::string id) {
	return print(R"({ "id" : "%"})", id);
}

std::string json_message_to_string(json_message const& m) {
	return print(R"({"index": %, "id": "%", "message": "%", "sender": { "id": "%", "me": % }})"
			, m.index, m.id, m.message, m.sender_kid.in_hex(), m.me ? "true" : "false");
}

std::string json_get_messages_result(std::vector<json_message> list) {
	std::string res = R"({ "data" : [)";
	bool first = true;
	for(auto e : list) {
		if(!first) {
			res += ", ";
		}
		first = false;
		res += json_message_to_string(e);
	}
	res += R"(]})";
	return res;
}

std::string json_get_messages(std::string id, std::optional<int> max, std::optional<bool> descending) {
	std::string res = print(R"({ "id": "%")", id);
	if(max) {
		res += print(R"(, "count": %)", *max);
	}
	if(descending) {
		res += print(R"(, "order": "%")", *descending ? "descending" : "ascending");
	}
	res += "}";
	return res;
}

std::string json_get_messages_chuck(std::string id, std::int64_t start, std::size_t count, std::optional<bool> descending) {
	std::string res = print(R"({ "id": "%", "start": %, "count": %)", id, start, count);
	if(descending) {
		res += print(R"(, "order": "%")", *descending ? "descending" : "ascending");
	}
	res += "}";
	return res;
}

static json_message plain_message(json::object const& obj) {
	return json_message{
				extract<std::int64_t>(obj, "index"),
				extract<std::string>(obj, "id"),
				extract<std::string>(obj, "message"),
				crypto::public_key_id{extract<std::string>(extract<json::object>(obj, "sender"), "id")},
				extract<bool>(extract<json::object>(obj, "sender"), "me")};
}

std::vector<json_message> list_plain_messages(json::array const& msg_arr) {
	std::vector<json_message> res;
	CHECK_NOTHROW([&]{
		for(auto const& v : msg_arr) {
			auto obj = v.as_object();
			res.push_back(plain_message(obj));
		}
	}());
	return res;
}

std::vector<json_message> list_messages(std::string str) {
	std::vector<json_message> res;
	CAPTURE(str);
	CHECK_NOTHROW([&]{
		auto obj = json::parse(str).as_object();
		auto msg_arr = extract<json::array>(obj, "data");
		res = list_plain_messages(msg_arr);
	}());
	return res;
}

json_send_message_result::json_send_message_result(std::string str)
{
	CHECK_NOTHROW([&]{
		auto obj = json::parse(str).as_object();
		message = plain_message(obj);
		id = message.id;
	}());
}

std::string json_send_message(std::string chat_id, std::string message) {
	return print(R"({ "id" : "%", "message": "%"})", chat_id, message);
}

std::string json_share_file(std::string chat_id, std::string path, std::string name, std::string mime) {
	return print(R"({ "id" : "%", "path": "%", "name": "%", "mime": "%"})", chat_id, path, name, mime);
}

static json_file plain_file(json::object const& obj) {
	return json_file{
		extract<std::int64_t>(obj, "index"),
		extract<std::string>(obj, "file"),
		extract<std::string>(obj, "name"),
		extract<std::string>(obj, "mime"),
		extract<std::uint64_t>(obj, "size"),
		extract<std::string>(obj, "state"),
		crypto::public_key_id{extract<std::string>(extract<json::object>(obj, "sharer"), "id")},
		extract<bool>(extract<json::object>(obj, "sharer"), "me")};
}

json_file json_file_result(std::string str) {
	json_file res;
	CAPTURE(str);
	CHECK_NOTHROW([&]{ res = plain_file(json::parse(str).as_object()); }());
	return res;
}

std::string json_get_files(std::string chat_id) {
	return print(R"({ "id": "%"})", chat_id);
}

std::vector<json_file> list_files(std::string str) {
	std::vector<json_file> res;
	CAPTURE(str);
	CHECK_NOTHROW([&]{
		for(auto const& v : extract<json::array>(json::parse(str).as_object(), "data")) {
			res.push_back(plain_file(v.as_object()));
		}
	}());
	return res;
}

std::string json_file_command(std::string chat_id, std::string file_id, std::optional<std::string> path) {
	std::string res = print(R"({ "id": "%", "file": "%")", chat_id, file_id);
	if(path) {
		res += print(R"(, "path": "%")", *path);
	}
	return res + "}";
}

std::string json_handle_qr_code_user(json_contact user) {
	return print(R"(sp-gc:{
			"type":"user",
			"data" : {
				"name" : "%",
				"id": "%"
			}
			})", user.name, user.kid.in_hex());
}

std::string json_handle_qr_code_user_result(json_contact user) {
	return R"({"type":"user", "data": )" + json_add_contact_result(user) + "}";
}

std::string json_handle_qr_code_join(std::string chat_id) {
	return print(R"(sp-gc:{ "type":"join", "data": {"id": "%"} })", chat_id);
}

std::string json_handle_qr_code_join_result(std::string chat_id) {
	return print(R"({"type":"join", "data": {"id" : "%"}})", chat_id);
}

static json::object request_to_json(json_request r) {
	return json::object{
		{"action", r.action},
		{"state", r.state},
		{"requestid", r.id},
		{"sender", json::object
			{
				{"id", r.sender.in_hex()},
				{"name", r.user_name}
			}},
		{"message", r.message}};
}

static json_request plain_request(json::object const& obj) {
	return json_request{
				extract<std::int64_t>(obj, "requestid"),
				crypto::public_key_id{extract<std::string>(extract<json::object>(obj, "sender"), "id")},
				extract<std::string>(obj, "state"),
				extract<std::string>(extract<json::object>(obj, "sender"), "name"),
				extract<std::string>(obj, "message"),
				extract<std::string>(obj, "action")};
}

std::string json_get_requests_result(std::vector<json_request> list) {
	json::array arr;
	for(auto&& v : list) {
		arr.push_back(request_to_json(v));
	}
	return json::serialize(json::object{{"data", arr}});
}

std::string json_request_action(std::int64_t id, std::string action) {
	return print(R"({"requestid": %, "action": "%"})", id, action);
}

std::vector<json_request> list_requests(std::string str) {
	std::vector<json_request> res;
	CAPTURE(str);
	CHECK_NOTHROW([&]{
		auto obj = json::parse(str).as_object();
		auto arr = extract<json::array>(obj, "data");
		for(auto const& v : arr) {
			res.push_back(plain_request(v.as_object()));
		}
	}());
	return res;
}

}