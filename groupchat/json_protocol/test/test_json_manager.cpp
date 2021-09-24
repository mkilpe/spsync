
#include "json_test_helpers.hpp"

#include <groupchat/json_protocol/json_helpers.hpp>
#include <groupchat/json_protocol/json_manager.hpp>
#include <groupchat/core/groupchat.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/util/print_util.hpp>

#include <spsync/test/test_server_runner.hpp>
#include <spsync/test/test_context.hpp>

namespace securepath::groupchat::json_protocol::test {

TEST_CASE("json_manager_test", "[system]") {
	std::remove(groupchat_config{"client_1"}.db().c_str());
	std::remove(groupchat_config{"client_2"}.db().c_str());

	sync::test::test_context net_context;
	net_context.add_client(2);

	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	{
		json_manager manager(net_context.client_context(0), [](auto){}, "client_1");
		CHECK_EQUAL_JSON(manager.get_account(), R"({})");
		{
			CHECK_JSON(manager.create_account(R"({"name": "test", "server": { "host": "127.0.0.1"} })")
				, R"({ "user" : { "name": "test" }})");
		}
		CHECK_JSON(manager.get_account(), R"({ "user" : { "name": "test" }})");
	}
	{
		json_manager manager(net_context.client_context(0), [](auto){}, "client_1");
		CHECK_JSON(manager.get_account(), R"({ "user" : { "name": "test" }})");
	}
	{ // create second account
		json_manager manager(net_context.client_context(1), [](auto){}, "client_2");
		CHECK_JSON(manager.create_account(R"({"name": "test contact", "server": { "host": "127.0.0.1"} })")
			, R"({ "user" : { "name": "test contact" }})");
		CHECK_JSON(manager.get_account(), R"({ "user" : { "name": "test contact" }})");
	}
	{ // contacts
		json_manager manager(net_context.client_context(0), [](auto){}, "client_1");
		CHECK_JSON(manager.get_account(), R"({ "user" : { "name": "test" }})");

		CHECK_EQUAL_JSON(manager.connect(), "{}");
		CHECK_EQUAL_JSON(manager.disconnect(), "{}");

		auto contact_key = net_context.key_id(1).in_hex();

		CHECK_JSON(manager.get_contacts(""), R"({ "data" : []})");

		auto contact_res = print(R"({ "name" : "my contact", "key_id": "%", "id": "%" })", contact_key, contact_key);
		CHECK_JSON(manager.add_contact(print(R"({ "name" : "my contact", "key_id": "%"})", contact_key)), contact_res);
		CHECK_JSON(manager.get_contacts(""), print(R"({ "data" : [%] })", contact_res));

		CHECK_JSON(manager.add_contact(print(R"({ "name" : "my contact", "key_id": "%"})", contact_key)), R"({ "error" : {}})");
	}
	{ // chats
		json_manager manager1(net_context.client_context(0), [](auto){}, "client_1");
		json_manager manager2(net_context.client_context(1), [](auto){}, "client_2");

		CHECK_EQUAL_JSON(manager1.get_chats(""), R"({ "data" : []})");
		CHECK_EQUAL_JSON(manager2.get_chats(""), R"({ "data" : []})");

		auto user_key = net_context.key_id(1).in_hex();
		auto cres = manager1.create_chat(print(R"({ "name" : "test chat", "members" : [{"user": "%"}] })", user_key));
		CHECK_JSON(cres, R"({ "name" : "test chat" })");
		std::string id = extract<std::string>(json::parse(cres).as_object(), "id"); // get the chat id

		CHECK_JSON(manager1.get_chats(""), print(R"({"data" : [{"name": "test chat", "id": "%"}] })", id));

		//this not working currently
		//CHECK_EQUAL_JSON(manager1.change_chat_member(print(R"({ "chat_id" : "%", "add" : [{"user": "%"}] })", id, user_key)), "{}");

		CHECK_JSON(manager1.get_chat_members(print(R"({ "chat_id" : "%"})", id))
			, print(R"({ "data" : [{"name": "my contact", "key_id": "%", "is_contact": true}] })", user_key));

		CHECK_JSON(manager2.join_chat(print(R"({ "chat_id" : "%"})", id)), print(R"({ "id" : "%"})", id));
		WAIT(check_contains_json(manager2.get_chat_members(print(R"({ "chat_id" : "%"})", id))
			, print(R"({ "data" : [{"key_id": "%", "is_contact": false}] })", user_key)), 2s);

		CHECK_JSON(manager2.get_chat_members(print(R"({ "chat_id" : "%"})", id))
			, print(R"({ "data" : [{"key_id": "%", "is_contact": false}] })", user_key));
		REQUIRE(check_contains_json(manager2.get_chat_members(print(R"({ "chat_id" : "%"})", id))
			, print(R"({ "data" : [{"key_id": "%", "is_contact": false}] })", user_key)));


		CHECK_EQUAL_JSON(manager1.get_messages(print(R"({ "chat_id": "%"})", id)), R"({ "data": []})");
		CHECK_EQUAL_JSON(manager2.get_messages(print(R"({ "chat_id": "%"})", id)), R"({ "data": []})");

		auto res = manager1.send_message(print(R"({ "chat_id" : "%", "message": "test message"})", id));
		auto mid = extract_opt<std::string>(json::parse(res).as_object(), "message_id");
		REQUIRE(mid);

		CHECK_JSON(manager1.get_messages(print(R"({ "chat_id" : "%"})", id)),
			print(R"({ "data" : [
				{"seq": 2,
				 "message_id": "%",
				 "messages": "test message",
				 "sender": {
				 	"name": "my contact",
				 	"key_id": "%",
				 	"is_contact": true
				 }
				}] })", *mid, user_key));
	}
}

}