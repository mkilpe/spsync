
#include "json_test_helpers.hpp"
#include "json_commands.hpp"

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
		CHECK_EQUAL_JSON(manager.get_account(), "{}");
		{
			CHECK_JSON(manager.create_account(json_create_account("test")), json_create_account_result("test"));
		}
		CHECK_JSON(manager.get_account(), json_get_account_result("test"));
	}
	{
		json_manager manager(net_context.client_context(0), [](auto){}, "client_1");
		CHECK_JSON(manager.get_account(), json_get_account_result("test"));
	}
	{ // create second account
		json_manager manager(net_context.client_context(1), [](auto){}, "client_2");
		CHECK_JSON(manager.create_account(json_create_account("test contact")), json_create_account_result("test contact"));
		CHECK_JSON(manager.get_account(), json_get_account_result("test contact"));
	}
	{ // create third account
		json_manager manager(net_context.client_context(2), [](auto){}, "client_3");
		CHECK_JSON(manager.create_account(json_create_account("some")), json_create_account_result("some"));
		CHECK_JSON(manager.get_account(), json_get_account_result("some"));
	}
	{ // contacts
		json_manager manager(net_context.client_context(0), [](auto){}, "client_1");
		CHECK_JSON(manager.get_account(), json_get_account_result("test"));

		CHECK_EQUAL_JSON(manager.connect(), "{}");
		CHECK_EQUAL_JSON(manager.disconnect(), "{}");

		CHECK_JSON(manager.get_contacts(""), json_get_contacts_result({}));

		CHECK_JSON(manager.add_contact(json_add_contact({"my contact", net_context.key_id(1)}))
			, json_add_contact_result({"my contact", net_context.key_id(1)}));
		CHECK_JSON(manager.get_contacts(""), json_get_contacts_result({json_contact{"my contact", net_context.key_id(1)}}));

		CHECK_JSON(manager.add_contact(json_add_contact({"my contact", net_context.key_id(1)})), R"({ "error" : {}})");

		//add third as contact too so we can create chat later on (this causes the client to download the key)
		CHECK_JSON(manager.add_contact(json_add_contact({"my other contact", net_context.key_id(2)}))
			, json_add_contact_result({"my other contact", net_context.key_id(2)}));
	}

	//chat id
	std::string id;
	{ // chats
		json_manager manager1(net_context.client_context(0), [](auto){}, "client_1");
		json_manager manager2(net_context.client_context(1), [](auto){}, "client_2");

		CHECK_EQUAL_JSON(manager1.get_chats(""), json_get_chats_result({}));
		CHECK_EQUAL_JSON(manager2.get_chats(""), json_get_chats_result({}));

		json_create_chat_result cc_res = manager1.create_chat(
			json_create_chat("test chat", {net_context.key_id(1), net_context.key_id(2)}));

		CHECK(cc_res.result.name == "test chat");
		REQUIRE(!cc_res.result.id.empty());
		id = cc_res.result.id;

		CHECK_JSON(manager1.get_chats(""), json_get_chats_result({{"test chat", cc_res.result.id}}));

		//this not working currently
		//CHECK_EQUAL_JSON(manager1.change_chat_member(print(R"({ "chat_id" : "%", "add" : [{"user": "%"}] })", id, user_key)), "{}");

		CHECK_JSON(manager1.get_chat_members(json_get_chat_members(id))
			, json_get_chat_members_result({{"my contact", net_context.key_id(1), true}}));

		CHECK_JSON(manager2.join_chat(json_join_chat(id)), json_join_chat_result(id));

		WAIT_REQUIRE_JSON(manager2.get_chat_members(json_get_chat_members(id))
			, json_get_chat_members_result({{net_context.key_id(1).in_hex(), net_context.key_id(1), false}}), 2s);

		CHECK_EQUAL_JSON(manager1.get_messages(json_get_messages(id)), json_get_messages_result({}));
		CHECK_EQUAL_JSON(manager2.get_messages(json_get_messages(id)), json_get_messages_result({}));

		{
			json_send_message_result res = manager1.send_message(json_send_message(id, "test message"));
			REQUIRE(!res.id.empty());

			//note: oneself not considered as contact
			WAIT_CHECK_JSON(manager1.get_messages(json_get_messages(id))
				, json_get_messages_result({{2, res.id, "test message", net_context.key_id(0)}}), 2s);

			WAIT_CHECK_JSON(manager2.get_messages(json_get_messages(id))
				, json_get_messages_result({{2, res.id, "test message", net_context.key_id(0)}}), 2s);
		}
		{
			json_send_message_result res = manager2.send_message(json_send_message(id, "other message"));
			REQUIRE(!res.id.empty());

			WAIT_CHECK_JSON(manager2.get_messages(json_get_messages(id))
				, json_get_messages_result({{3, res.id, "other message", net_context.key_id(1)}}), 2s);

			WAIT_CHECK_JSON(manager1.get_messages(json_get_messages(id))
				, json_get_messages_result({{3, res.id, "other message", net_context.key_id(1)}}), 2s);
		}
	}
	{ //qr code
		json_manager manager3(net_context.client_context(2), [](auto){}, "client_3");

		CHECK_JSON(manager3.handle_qr_code(
			json_handle_qr_code_user(json_contact{"qr code test", net_context.key_id(0)}))
			, json_handle_qr_code_user_result(json_contact{"qr code test", net_context.key_id(0)}));

		CHECK_JSON(manager3.handle_qr_code(json_handle_qr_code_join(id)), json_handle_qr_code_join_result(id));

		WAIT_REQUIRE_JSON(manager3.get_chat_members(json_get_chat_members(id))
			, json_get_chat_members_result({{net_context.key_id(1).in_hex(), net_context.key_id(1), false}}), 2s);
	}
}

}