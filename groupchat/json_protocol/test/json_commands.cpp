#include "json_commands.hpp"

#include <securepath/util/print_util.hpp>

namespace securepath::groupchat::json_protocol::test {

std::string json_get_account_result(std::string name) {
	return print(R"({ "user" : { "name": "%" } })", name);
}

std::string json_create_account(std::string name) {
	return print(R"({ "name": "%", "server": { "host": "127.0.0.1"} })", name);
}

std::string json_create_account_result(std::string name) {
	return print(R"({ "user" : { "name": "%" } })", name);
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

std::string json_add_contact(json_contact c) {
	return print(R"({ "name" : "%", "key_id": "%"})", c.name, c.kid.in_hex());
}

std::string json_add_contact_result(json_contact c) {
	auto kid_str = c.kid.in_hex();
	return print(R"({ "name" : "%", "key_id": "%", "id": "%" })", c.name, kid_str, kid_str);
}

std::string json_get_chats_result(std::vector<json_chat> list) {
	std::string res = R"({ "data" : [)";
	bool first = true;
	for(auto e : list) {
		if(!first) {
			res += ", ";
		}
		first = false;
		res += print(R"({"name": "%", "id": "%"})", e.name, e.id);
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

std::string json_get_chat_members_result(std::vector<json_chat_member> list) {
	std::string res = R"({ "data" : [)";
	bool first = true;
	for(auto e : list) {
		if(!first) {
			res += ", ";
		}
		first = false;
		res += print(R"({"name": "%", "key_id": "%", "is_contact" : %})", e.name, e.kid.in_hex(), e.is_contact ? "true" : "false");
	}
	res += R"(]})";
	return res;
}

std::string json_get_chat_members(std::string id) {
	return print(R"({ "chat_id" : "%"})", id);
}

std::string json_join_chat(std::string id) {
	return print(R"({ "chat_id" : "%"})", id);
}

std::string json_join_chat_result(std::string id) {
	return print(R"({ "id" : "%"})", id);
}

std::string json_get_messages_result(std::vector<json_message> list) {
	std::string res = R"({ "data" : [)";
	bool first = true;
	for(auto e : list) {
		if(!first) {
			res += ", ";
		}
		first = false;
		res += print(R"({"seq": %, "message_id": "%", "message": "%", "sender": { "key_id": "%" }})"
			, e.seq, e.id, e.message, e.sender_kid.in_hex());
	}
	res += R"(]})";
	return res;
}

std::string json_get_messages(std::string id) {
	return print(R"({ "chat_id": "%"})", id);
}

json_send_message_result::json_send_message_result(std::string str)
{
	CHECK_NOTHROW([&]{
		auto obj = json::parse(str).as_object();
		id = extract<std::string>(obj, "message_id");
	}());
}

std::string json_send_message(std::string chat_id, std::string message) {
	return print(R"({ "chat_id" : "%", "message": "%"})", chat_id, message);
}

std::string json_handle_qr_code_user(json_contact user) {
	return print(R"(sp-gc:{
			"type":"user",
			"data" : {
				"name" : "%",
				"key_id": "%"
			}
			})", user.name, user.kid.in_hex());
}

std::string json_handle_qr_code_user_result(json_contact user) {
	return R"({"type":"user", "data": )" + json_add_contact_result(user) + "}";
}

std::string json_handle_qr_code_join(std::string chat_id) {
	return print(R"(sp-gc:{ "type":"join", "data": {"chat_id": "%"} })", chat_id);
}

std::string json_handle_qr_code_join_result(std::string chat_id) {
	return print(R"({"type":"join", "data": {"id" : "%"}})", chat_id);
}

}