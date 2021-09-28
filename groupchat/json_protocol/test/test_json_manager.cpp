
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
	std::remove(groupchat_config{"client_3"}.db().c_str());

	sync::test::test_context net_context;
	net_context.add_client(3);

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
	{ // create third account
		json_manager manager(net_context.client_context(2), [](auto){}, "client_3");
		CHECK_JSON(manager.create_account(R"({"name": "some", "server": { "host": "127.0.0.1"} })")
			, R"({ "user" : { "name": "some" }})");
		CHECK_JSON(manager.get_account(), R"({ "user" : { "name": "some" }})");
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

		//add third as contact too so we can create chat later on (this causes the client to download the key)
		CHECK_JSON(manager.add_contact(print(R"({
				"name" : "my other contact",
				"key_id": "%"
			})", net_context.key_id(2).in_hex())), print(R"({
					"name" : "my other contact",
					"key_id": "%", "id": "%"
				})", net_context.key_id(2).in_hex(), net_context.key_id(2).in_hex()));
	}

	//chat id
	std::string id;
	{ // chats
		json_manager manager1(net_context.client_context(0), [](auto){}, "client_1");
		json_manager manager2(net_context.client_context(1), [](auto){}, "client_2");

		CHECK_EQUAL_JSON(manager1.get_chats(""), R"({ "data" : []})");
		CHECK_EQUAL_JSON(manager2.get_chats(""), R"({ "data" : []})");

		auto user_key = net_context.key_id(1).in_hex();
		auto cres = manager1.create_chat(print(R"({ "name" : "test chat", "members" : [{"user": "%"}, {"user": "%"}] })", user_key, net_context.key_id(2).in_hex()));
		CHECK_JSON(cres, R"({ "name" : "test chat" })");
		id = extract<std::string>(json::parse(cres).as_object(), "id"); // get the chat id

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

		{
			auto res = manager1.send_message(print(R"({ "chat_id" : "%", "message": "test message"})", id));
			auto mid = extract_opt<std::string>(json::parse(res).as_object(), "message_id");
			REQUIRE(mid);

			WAIT(check_contains_json(manager1.get_messages(print(R"({ "chat_id": "%"})", id))
				, print(R"({ "data": [{"message_id": "%"}] })", *mid)), 2s);

			//note, oneself not considered as contact
			CHECK_JSON(manager1.get_messages(print(R"({ "chat_id" : "%"})", id)),
				print(R"({ "data" : [
					{"seq": 2,
					 "message_id": "%",
					 "message": "test message",
					 "sender": {
					 	"key_id": "%",
					 	"is_contact": false
					 }
					}] })", *mid, net_context.key_id(0).in_hex()));

			WAIT(check_contains_json(manager2.get_messages(print(R"({ "chat_id": "%"})", id))
				, print(R"({ "data": [{"message_id": "%"}] })", *mid)), 2s);

			CHECK_JSON(manager1.get_messages(print(R"({ "chat_id" : "%"})", id)),
				print(R"({ "data" : [
					{"seq": 2,
					 "message_id": "%",
					 "message": "test message",
					 "sender": {
					 	"key_id": "%",
					 	"is_contact": false
					 }
					}] })", *mid, net_context.key_id(0).in_hex()));
		}
		{
			auto res = manager2.send_message(print(R"({ "chat_id" : "%", "message": "other message"})", id));
			auto mid = extract_opt<std::string>(json::parse(res).as_object(), "message_id");
			REQUIRE(mid);

			WAIT(check_contains_json(manager2.get_messages(print(R"({ "chat_id": "%"})", id))
				, print(R"({ "data": [{"message_id": "%"}] })", *mid)), 2s);

			//note, oneself not considered as contact
			CHECK_JSON(manager2.get_messages(print(R"({ "chat_id" : "%"})", id)),
				print(R"({ "data" : [
					{"seq": 3,
					 "message_id": "%",
					 "message": "other message",
					 "sender": {
					 	"key_id": "%",
					 	"is_contact": false
					 }
					}] })", *mid, net_context.key_id(1).in_hex()));

			WAIT(check_contains_json(manager1.get_messages(print(R"({ "chat_id": "%"})", id))
				, print(R"({ "data": [{"message_id": "%"}] })", *mid)), 2s);

			CHECK_JSON(manager1.get_messages(print(R"({ "chat_id" : "%"})", id)),
				print(R"({ "data" : [
					{"seq": 3,
					 "message_id": "%",
					 "message": "other message",
					 "sender": {
					 	"name": "my contact",
					 	"key_id": "%",
					 	"is_contact": true
					 }
					}] })", *mid, net_context.key_id(1).in_hex()));
		}
	}
	{ //qr code
		json_manager manager3(net_context.client_context(2), [](auto){}, "client_3");

		auto contact_key = net_context.key_id(0).in_hex();
		auto contact_res = print(R"({"type":"user", "data": { "name" : "qr code test", "key_id": "%", "id": "%" }})", contact_key, contact_key);
		CHECK_JSON(manager3.handle_qr_code(print(R"(sp-gc:{
			"type":"user",
			"data" : {
				"name" : "qr code test",
				"key_id": "%"
			}
			})", contact_key)), contact_res);

		CHECK_JSON(manager3.handle_qr_code(print(R"(sp-gc:{
			"type":"join",
			"data" : {"chat_id" : "%"}})", id))
			, print(R"({
				"type":"join", "data": {"id" : "%"}})", id));

		WAIT(check_contains_json(manager3.get_chat_members(print(R"({ "chat_id" : "%"})", id))
			, print(R"({ "data" : [{"key_id": "%", "is_contact": false}] })", net_context.key_id(1).in_hex())), 2s);

		CHECK_JSON(manager3.get_chat_members(print(R"({ "chat_id" : "%"})", id))
			, print(R"({ "data" : [{"key_id": "%", "is_contact": false}] })", net_context.key_id(1).in_hex()));
		REQUIRE(check_contains_json(manager3.get_chat_members(print(R"({ "chat_id" : "%"})", id))
			, print(R"({ "data" : [{"key_id": "%", "is_contact": false}] })", net_context.key_id(1).in_hex())));
	}
}

}