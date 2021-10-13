#pragma once

#include <groupchat/json_protocol/json_helpers.hpp>

#include <securepath/crypto/public_key_id.hpp>
#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::groupchat::json_protocol::test {

std::string json_get_account_result(std::string name);
std::string json_create_account(std::string name);
std::string json_create_account_result(std::string name);

struct json_contact {
	std::string name;
	crypto::public_key_id kid;
};
std::string json_get_contacts_result(std::vector<json_contact>);
std::string json_add_contact(json_contact);
std::string json_add_contact_result(json_contact);

struct json_message {
	std::int64_t index;
	std::string id;
	std::string message;
	crypto::public_key_id sender_kid;

	auto operator<=>(json_message const&) const = default;
};

std::string json_message_to_string(json_message const& m);
std::string json_get_messages_result(std::vector<json_message>);
std::string json_get_messages(std::string, std::optional<int> max = std::nullopt, std::optional<bool> descending = std::nullopt);
std::string json_get_messages_chuck(std::string, std::int64_t start, std::size_t count, std::optional<bool> descending = std::nullopt);
std::vector<json_message> list_plain_messages(json::array const&);
std::vector<json_message> list_messages(std::string);

struct json_send_message_result {
	json_send_message_result(std::string);
	std::string id;
	json_message message;
};
std::string json_send_message(std::string, std::string);

struct json_chat {
	std::string name;
	std::string id;
	std::vector<json_message> messages;
};
std::string json_get_chats_result(std::vector<json_chat>);
std::string json_create_chat(std::string name, std::vector<crypto::public_key_id>);
struct json_create_chat_result {
	json_create_chat_result(std::string);
	json_chat result;
};
std::vector<json_chat> list_chats(std::string);

struct json_chat_member {
	std::string name;
	crypto::public_key_id kid;
	bool is_contact;
};
std::string json_get_chat_members_result(std::vector<json_chat_member>);
std::string json_get_chat_members(std::string);
std::string json_join_chat(std::string);
std::string json_join_chat_result(std::string);

std::string json_handle_qr_code_user(json_contact);
std::string json_handle_qr_code_user_result(json_contact);
std::string json_handle_qr_code_join(std::string);
std::string json_handle_qr_code_join_result(std::string);

}