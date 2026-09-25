// SPDX-License-Identifier: MIT

#include "json_test_helpers.hpp"
#include <filesystem>
#include <future>
#include <mutex>
#include <spsync/util/print.hpp>
#include "json_test_manager.hpp"
#include "json_commands.hpp"

#include <groupchat/json_protocol/json_helpers.hpp>
#include <groupchat/json_protocol/json_manager.hpp>
#include <groupchat/core/groupchat.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/util/print_util.hpp>

#include <spsync/test/test_server_runner.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/core/data/data_ticket.hpp>
#include <spsync/protocol/ports.hpp>

#include <securepath/crypto/hash.hpp>
#include <securepath/crypto/private_data_access.hpp>

#include <fstream>

namespace securepath::groupchat::json_protocol::test {

namespace {

/// the test server with the data role (shared_files.txt), the way a deployment enables it
sync::spsync_server_params data_role_params(sync::test::test_context& net_context) {
	std::filesystem::remove_all("json_test_server");
	auto const server_key = crypto::my_private_key(net_context.server_context().private_data());
	sync::spsync_server_params params;
	params.storage_params.storage_root = "json_test_server";
	params.storage_params.data_servers = {sync::data_endpoint{"127.0.0.1", sync::default_data_server_port, server_key.id(), {}, {}}};
	params.data_params.enabled = true;
	params.data_params.storage_root = "json_test_server";
	return params;
}

/// a file of random content; its sha3
octet_vector write_random_file(std::filesystem::path const& path, std::size_t size) {
	auto const content = securepath::test::random_octet_vector(size);
	std::ofstream out(path, std::ios::binary | std::ios::trunc);
	out.write(reinterpret_cast<char const*>(content.data()), static_cast<std::streamsize>(content.size()));
	crypto::hash_stream hash;
	hash.update(content);
	return hash.final();
}

/// the sha3 of a file
octet_vector file_digest(std::filesystem::path const& path) {
	std::ifstream in(path, std::ios::binary);
	octet_vector content{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
	crypto::hash_stream hash;
	hash.update(content);
	return hash.final();
}

/// (shared_files.txt SF 2) a file shared over the json commands: listed by the other
/// member on the server, fetched on demand, saved and read back, its local copy let go
void check_shared_files(json_test_manager& manager1, json_test_manager& manager2, std::string const& id
	, crypto::public_key_id const& sharer) {
	std::filesystem::create_directories("client_0");
	std::filesystem::create_directories("client_1");
	auto const digest = write_random_file("client_0/share.bin", 200000);

	auto const shared = json_file_result(manager1.share_file(json_share_file(id, "client_0/share.bin", "share.bin", "text/plain")));
	CHECK(!shared.id.empty());
	CHECK(shared.name == "share.bin");
	CHECK(shared.mime == "text/plain");
	CHECK(shared.size == 200000);
	CHECK(shared.state == "pending");
	CHECK(shared.sharer_kid == sharer);
	CHECK(shared.me);
	WAIT_CHECK(manager1.has_file_state_event(id, shared.id, "shared"), 20s);
	WAIT_CHECK(manager1.has_file_event(id, shared.id), 5s);

	// the other member lists it on the server, fetches, saves and reads it back
	WAIT_CHECK(list_files(manager2.get_files(json_get_files(id))).size() == 1, 10s);
	auto const listed = list_files(manager2.get_files(json_get_files(id))).at(0);
	CHECK(listed.id == shared.id);
	CHECK(listed.name == "share.bin");
	CHECK(listed.size == 200000);
	CHECK(listed.state == "on_server");
	CHECK(!listed.me);
	WAIT_CHECK(manager2.has_file_event(id, shared.id), 5s);
	CHECK_EQUAL_JSON(manager2.fetch_file(json_file_command(id, shared.id)), "{}");
	WAIT_CHECK(manager2.has_file_state_event(id, shared.id, "fetched"), 30s);
	CHECK_EQUAL_JSON(manager2.save_file(json_file_command(id, shared.id, "client_1/got.bin")), "{}");
	CHECK(file_digest("client_1/got.bin") == digest);
	CHECK_EQUAL_JSON(manager2.remove_file(json_file_command(id, shared.id)), "{}");
	CHECK(list_files(manager2.get_files(json_get_files(id))).at(0).state == "removed");
}

}

TEST_CASE("json_manager_test", "[system]") {

	sync::test::test_context net_context;
	net_context.add_client(3);

	sync::test::test_server server(net_context.server_context(), data_role_params(net_context));
	server.run();

	{
		json_test_manager manager(net_context, 0, remove_db);
		CHECK_EQUAL_JSON(manager.get_account(), "{}");
		CHECK_JSON(manager.create_account(json_create_account("test")), json_create_account_result("test"));
		CHECK_JSON(manager.get_account(), json_get_account_result("test"));
	}
	{
		json_test_manager manager(net_context, 0, keep_db);
		CHECK_JSON(manager.get_account(), json_get_account_result("test"));
	}
	{ // create second account
		json_test_manager manager(net_context, 1, remove_db);
		CHECK_JSON(manager.create_account(json_create_account("test contact")), json_create_account_result("test contact"));
		CHECK_JSON(manager.get_account(), json_get_account_result("test contact"));
	}
	{ // create third account
		json_test_manager manager(net_context, 2, remove_db);
		CHECK_JSON(manager.create_account(json_create_account("some")), json_create_account_result("some"));
		CHECK_JSON(manager.get_account(), json_get_account_result("some"));
	}
	{ // contacts
		json_test_manager manager1(net_context, 0, keep_db);
		json_test_manager manager2(net_context, 1, keep_db);
		CHECK_JSON(manager1.get_account(), json_get_account_result("test"));

		CHECK_EQUAL_JSON(manager1.connect(), "{}");
		WAIT_CHECK(manager1.has_connect_event(), 2s);

		// calling connect should work and emit the event again
		CHECK_EQUAL_JSON(manager1.connect(), "{}");
		WAIT_CHECK(manager1.has_connect_event(), 2s);

		CHECK_EQUAL_JSON(manager1.disconnect(), "{}");
		WAIT_CHECK(manager1.has_disconnect_event(), 2s);

		// calling disconnect should work and emit the event again
		CHECK_EQUAL_JSON(manager1.disconnect(), "{}");
		WAIT_CHECK(manager1.has_disconnect_event(), 2s);

		CHECK_EQUAL_JSON(manager1.connect(), "{}");
		CHECK_EQUAL_JSON(manager2.connect(), "{}");

		//WAIT_CHECK(manager1.has_connect_event(), 2s); //what to do with packet server connect?
		//WAIT_CHECK(manager2.has_connect_event(), 2s);

		CHECK_JSON(manager1.get_contacts(""), json_get_contacts_result({}));

		CHECK_JSON(manager1.add_contact(json_add_contact({"my test contact", net_context.key_id(1)}, "test msg"))
			, json_add_contact_result({"my test contact", net_context.key_id(1)}));
		CHECK_JSON(manager1.get_contacts(""), json_get_contacts_result({json_contact{"my test contact", net_context.key_id(1)}}));

		WAIT_CHECK(manager2.has_contacting_event(net_context.key_id(0), "test", "test msg"), 2s);

		manager2.add_contact(json_add_contact({"test", net_context.key_id(0)}, "test msg"));
		CHECK_JSON(manager2.get_contacts(""), json_get_contacts_result({json_contact{"test", net_context.key_id(0)}}));

		// change already existing contact
		CHECK_JSON(manager1.add_contact(json_add_contact({"my contact", net_context.key_id(1)}, "test"))
			, json_add_contact_result({"my contact", net_context.key_id(1)}));

		//try to create chat without having member as contact (we don't have the key yet)
		CHECK_JSON(manager1.create_chat(
			json_create_chat("test chat", {net_context.key_id(1), net_context.key_id(2)})), R"({ "error" : {}})");

		//add third as contact too so we can create chat later on (this causes the client to download the key)
		CHECK_JSON(manager1.add_contact(json_add_contact({"my other contact", net_context.key_id(2)}, ""))
			, json_add_contact_result({"my other contact", net_context.key_id(2)}));

		WAIT_CHECK(manager1.has_connect_event(), 2s);
	}

	//chat id
	std::string id;
	{ // chats
		json_test_manager manager1(net_context, 0, keep_db);
		json_test_manager manager2(net_context, 1, keep_db);

		CHECK_EQUAL_JSON(manager1.get_chats(""), json_get_chats_result({}));
		CHECK_EQUAL_JSON(manager2.get_chats(""), json_get_chats_result({}));

		json_create_chat_result cc_res = manager1.create_chat(
			json_create_chat("test chat", {net_context.key_id(1), net_context.key_id(2)}));

		CHECK(cc_res.result.name == "test chat");
		REQUIRE(!cc_res.result.id.empty());
		id = cc_res.result.id;

		{ // see we can create second one
			json_create_chat_result cc_res = manager1.create_chat(json_create_chat("other chat", {}));
			REQUIRE(!cc_res.result.id.empty());
		}

		CHECK_JSON(manager1.get_chats(""), json_get_chats_result({{"test chat", cc_res.result.id}}));
		WAIT_CHECK(manager1.has_create_event(cc_res.result.id), 2s);

		//this not working currently
		//CHECK_EQUAL_JSON(manager1.change_chat_member(print(R"({ "chat_id" : "%", "add" : [{"user": "%"}] })", id, user_key)), "{}");

		CHECK_JSON(manager1.get_chat_members(json_get_chat_members(id))
			, json_get_chat_members_result({{"my contact", net_context.key_id(1), true}}));

		CHECK_JSON(manager2.join_chat(json_join_chat(id)), json_join_chat_result(id));
		WAIT_CHECK(manager2.has_join_event(id), 2s);

		WAIT_REQUIRE_JSON(manager2.get_chat_members(json_get_chat_members(id))
			, json_get_chat_members_result({{net_context.key_id(1).in_hex(), net_context.key_id(1), false}}), 2s);

		CHECK_EQUAL_JSON(manager1.get_messages(json_get_messages(id)), json_get_messages_result({}));
		CHECK_EQUAL_JSON(manager2.get_messages(json_get_messages(id)), json_get_messages_result({}));

		{
			json_send_message_result res = manager1.send_message(json_send_message(id, "test message"));
			REQUIRE(!res.id.empty());
			CHECK(res.message.id == res.id);
			CHECK(res.message.index == 1);
			CHECK(res.message.message == "test message");
			CHECK(res.message.sender_kid == net_context.key_id(0));

			//note: oneself not considered as contact
			WAIT_CHECK_JSON(manager1.get_messages(json_get_messages(id))
				, json_get_messages_result({{1, res.id, "test message", net_context.key_id(0), true}}), 2s);

			WAIT_CHECK_JSON(manager2.get_messages(json_get_messages(id))
				, json_get_messages_result({{1, res.id, "test message", net_context.key_id(0), false}}), 2s);

			WAIT_CHECK(manager1.has_message_event(id, res.id), 2s);
			WAIT_CHECK(manager2.has_message_event(id, res.id), 2s);
		}
		{
			json_send_message_result res = manager2.send_message(json_send_message(id, "other message"));
			REQUIRE(!res.id.empty());

			WAIT_CHECK_JSON(manager2.get_messages(json_get_messages(id))
				, json_get_messages_result({{2, res.id, "other message", net_context.key_id(1), true}}), 2s);

			WAIT_CHECK_JSON(manager1.get_messages(json_get_messages(id))
				, json_get_messages_result({{2, res.id, "other message", net_context.key_id(1), false}}), 2s);
		}
		check_shared_files(manager1, manager2, id, net_context.key_id(0));
	}
	{ //qr code
		json_test_manager manager3(net_context, 2, keep_db);

		CHECK_JSON(manager3.handle_qr_code(
			json_handle_qr_code_user(json_contact{"qr code test", net_context.key_id(0)}))
			, json_handle_qr_code_user_result(json_contact{"qr code test", net_context.key_id(0)}));

		CHECK_JSON(manager3.handle_qr_code(json_handle_qr_code_join(id)), json_handle_qr_code_join_result(id));

		WAIT_REQUIRE_JSON(manager3.get_chat_members(json_get_chat_members(id))
			, json_get_chat_members_result({{net_context.key_id(1).in_hex(), net_context.key_id(1), false}}), 2s);
	}
	{ //check chats there after constructing again
		json_test_manager manager(net_context, 0, keep_db);
		CHECK_JSON(manager.get_chats(""), json_get_chats_result({{"test chat", id}}));

		CHECK(!manager.has_connect_event());

		manager.connect();
		WAIT_CHECK(manager.has_connect_event(), 2s);
		manager.disconnect();
		WAIT_CHECK(manager.has_disconnect_event(), 2s);
	}
}


TEST_CASE("json_manager message test", "[system]") {
	int const count = 10;
	int const messages = 100;

	sync::test::test_context net_context;
	net_context.add_client(count);

	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	std::vector<std::unique_ptr<json_manager>> clients;

 	// create accounts
	for(int i = 0; i != count; ++i) {
		std::string client_str = print("client_%", i);
		clients.push_back(std::make_unique<json_test_manager>(net_context, i, remove_db));
		CHECK_JSON(clients.back()->create_account(json_create_account(client_str)), json_create_account_result(client_str));
		CHECK_JSON(clients.back()->get_account(), json_get_account_result(client_str));
	}

	// make contacts
	std::vector<json_contact> contacts;
	std::vector<crypto::public_key_id> keys;
	for(int i = 1; i != count; ++i) {
		keys.push_back(net_context.key_id(i));
		contacts.push_back(json_contact{print("contact %", i), net_context.key_id(i)});
		CHECK_JSON(clients[0]->add_contact(json_add_contact(contacts.back()))
			, json_add_contact_result({contacts.back().name, contacts.back().kid}));
	}

	CHECK_JSON(clients[0]->get_contacts(""), json_get_contacts_result(contacts));

	// create chat
	json_create_chat_result chat_res = clients[0]->create_chat(json_create_chat("test chat", keys));
	REQUIRE(!chat_res.result.id.empty());

	// join chat
	for(int i = 1; i != count; ++i) {
		CHECK_JSON(clients[i]->join_chat(json_join_chat(chat_res.result.id)), json_join_chat_result(chat_res.result.id));
	}

	// send messages
	for(int x = 0; x != messages; ++x) {
		for(int i = 0; i != count; ++i) {
			json_send_message_result res = clients[i]->send_message(json_send_message(chat_res.result.id, "test message"));
			REQUIRE(!res.id.empty());
		}
	}

	// wait to have all the messages
	for(int i = 0; i != count; ++i) {
		WAIT_CHECK(list_messages(clients[i]->get_messages(json_get_messages(chat_res.result.id))).size()
			 == count*messages, 30s);
	}

	// check the 'me' status
	for(int i = 0; i != count; ++i) {
		auto list = list_messages(clients[i]->get_messages(json_get_messages(chat_res.result.id)));
		for(auto v : list) {
			CHECK(v.me == (net_context.key_id(i) == v.sender_kid));
		}
	}
}

TEST_CASE("json_manager chat order test", "[system]") {
	sync::test::test_context net_context;
	net_context.add_client(1);

	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

 	json_test_manager manager(net_context, 0, remove_db);

	CHECK_JSON(manager.create_account(json_create_account("test")), json_create_account_result("test"));
	CHECK_JSON(manager.get_account(), json_get_account_result("test"));

	json_create_chat_result cc_res = manager.create_chat(json_create_chat("test chat", {}));
	REQUIRE(!cc_res.result.id.empty());
	std::string cid1 = cc_res.result.id;

	CHECK_JSON(manager.get_chats(""), json_get_chats_result({{"test chat", cid1}}));
	CHECK_JSON(manager.get_chats(R"({"message": {}})"), json_get_chats_result({{"test chat", cid1}}));
	CHECK_JSON(manager.get_chats(R"({"message": {"count": 5}})"), json_get_chats_result({{"test chat", cid1}}));
	CHECK_JSON(manager.get_chats(R"({"message": {"order": "ascending"}})"), json_get_chats_result({{"test chat", cid1}}));

	{
		auto chats = list_chats(manager.get_chats(""));
		REQUIRE(chats.size() == 1);
		CHECK(chats[0].messages.empty());
	}

	std::vector<json_message> messages;

	{
		json_send_message_result res = manager.send_message(json_send_message(cid1, "1"));
		REQUIRE(!res.id.empty());
		WAIT_CHECK_JSON(manager.get_messages(json_get_messages(cid1))
			, json_get_messages_result({{1, res.id, "1", net_context.key_id(0), true}}), 2s);
		messages.push_back(json_message{1, res.id, "1", net_context.key_id(0), true});
	}


	{
		auto chats = list_chats(manager.get_chats(""));
		REQUIRE(chats.size() == 1);
		CHECK(chats[0].messages.empty());
		CHECK(chats[0].id == cc_res.result.id);
	}
	{
		auto chats = list_chats(manager.get_chats(R"({"message": {}})"));
		REQUIRE(chats.size() == 1);
		REQUIRE(chats[0].messages.size() == 1);
		CHECK(chats[0].messages[0].id == messages.front().id);
	}

	for(int i = 0; i != 8; ++i) {
		std::string m = print("%", i+2);
		json_send_message_result res = manager.send_message(json_send_message(cid1, m));
		REQUIRE(!res.id.empty());
		messages.push_back(json_message{i+2, res.id, m, net_context.key_id(0), true});
	}

	WAIT_CHECK_JSON(manager.get_messages(json_get_messages(cid1))
		, json_get_messages_result(messages), 10s);

	{
		auto chats = list_chats(manager.get_chats(R"({"message": {}})"));
		REQUIRE(chats.size() == 1);
		REQUIRE(chats[0].messages.size() == 1);
		CHECK(chats[0].messages[0].id == messages.back().id);
	}
	{
		auto chats = list_chats(manager.get_chats(R"({"message": {"order": "ascending"}})"));
		REQUIRE(chats.size() == 1);
		REQUIRE(chats[0].messages.size() == 1);
		CHECK(chats[0].messages[0].id == messages.front().id);
	}
	{
		auto chats = list_chats(manager.get_chats(R"({"message": {"order": "descending"}})"));
		REQUIRE(chats.size() == 1);
		REQUIRE(chats[0].messages.size() == 1);
		CHECK(chats[0].messages[0].id == messages.back().id);
	}
	{
		auto chats = list_chats(manager.get_chats(R"({"message": {"count": 3}})"));
		REQUIRE(chats.size() == 1);
		REQUIRE(chats[0].messages.size() == 3);
		CHECK(chats[0].messages[0].id == messages.back().id);
		CHECK(chats[0].messages[1].id == messages[messages.size()-2].id);
		CHECK(chats[0].messages[2].id == messages[messages.size()-3].id);
	}
	{
		auto chats = list_chats(manager.get_chats(R"({"message": {"count": 4, "order": "ascending"}})"));
		REQUIRE(chats.size() == 1);
		REQUIRE(chats[0].messages.size() == 4);
		CHECK(chats[0].messages[0].id == messages[0].id);
		CHECK(chats[0].messages[1].id == messages[1].id);
		CHECK(chats[0].messages[2].id == messages[2].id);
		CHECK(chats[0].messages[3].id == messages[3].id);
	}
	{
		auto chats = list_chats(manager.get_chats(R"({"message": {"count": 2, "order": "descending"}})"));
		REQUIRE(chats.size() == 1);
		REQUIRE(chats[0].messages.size() == 2);
		CHECK(chats[0].messages[0].id == messages.back().id);
		CHECK(chats[0].messages[1].id == messages[messages.size()-2].id);
	}

	std::string cid2;
	std::string cid3;
	{
		json_create_chat_result cc_res = manager.create_chat(json_create_chat("test chat 2", {}));
		REQUIRE(!cc_res.result.id.empty());
		cid2 = cc_res.result.id;
	}
	{
		json_create_chat_result cc_res = manager.create_chat(json_create_chat("test chat 3", {}));
		REQUIRE(!cc_res.result.id.empty());
		cid3 = cc_res.result.id;
	}
	{
		CHECK_JSON(manager.get_chats(""), json_get_chats_result({
			{"test chat", cid1},
			{"test chat 2", cid2},
			{"test chat 3", cid3}}));

		auto chats = list_chats(manager.get_chats(""));
		REQUIRE(chats.size() == 3);
		CHECK(chats[0].messages.empty());
		CHECK(chats[1].messages.empty());
		CHECK(chats[2].messages.empty());
	}
	{
		json_send_message_result res = manager.send_message(json_send_message(cid2, "1"));
		REQUIRE(!res.id.empty());
		WAIT_CHECK_JSON(manager.get_messages(json_get_messages(cid2))
			, json_get_messages_result({{1, res.id, "1", net_context.key_id(0), true}}), 2s);
	}
	{
		CHECK_JSON(manager.get_chats(""), json_get_chats_result({
			{"test chat", cid1},
			{"test chat 2", cid2},
			{"test chat 3", cid3}}));

		auto chats = list_chats(manager.get_chats(""));
		REQUIRE(chats.size() == 3);
		CHECK(chats[0].messages.empty());
		CHECK(chats[1].messages.empty());
		CHECK(chats[2].messages.empty());
	}
	{
		auto chats = list_chats(manager.get_chats(R"({"message": {}})"));
		REQUIRE(chats.size() == 3);
		CHECK(chats[0].id == cid2);
		CHECK(chats[0].messages.size() == 1);
		CHECK(chats[1].id == cid1);
		CHECK(chats[1].messages.size() == 1);
		CHECK(chats[1].messages[0].id == messages.back().id);
		CHECK(chats[2].id == cid3);
		CHECK(chats[2].messages.size() == 0);
	}
	{
		json_send_message_result res = manager.send_message(json_send_message(cid1, "a"));
		REQUIRE(!res.id.empty());
		WAIT_CHECK_JSON(manager.get_messages(json_get_messages(cid1))
			, json_get_messages_result({{10, res.id, "a", net_context.key_id(0), true}}), 2s);
		messages.push_back(json_message{10, res.id, "a", net_context.key_id(0)});
	}
	{
		auto chats = list_chats(manager.get_chats(R"({"message": {"order": "descending"}})"));
		REQUIRE(chats.size() == 3);
		CHECK(chats[0].id == cid1);
		CHECK(chats[0].messages.size() == 1);
		CHECK(chats[0].messages[0].id == messages.back().id);
		CHECK(chats[1].id == cid2);
		CHECK(chats[1].messages.size() == 1);
		CHECK(chats[2].id == cid3);
		CHECK(chats[2].messages.size() == 0);
	}
	{
		auto chats = list_chats(manager.get_chats(R"({"message": {"order": "ascending"}})"));
		REQUIRE(chats.size() == 3);
		CHECK(chats[0].id == cid2);
		CHECK(chats[0].messages.size() == 1);
		CHECK(chats[1].id == cid1);
		CHECK(chats[1].messages.size() == 1);
		CHECK(chats[1].messages[0].id == messages.front().id);
		CHECK(chats[2].id == cid3);
		CHECK(chats[2].messages.size() == 0);
	}
}


TEST_CASE("json_manager message order test", "[system]") {
	sync::test::test_context net_context;
	net_context.add_client(1);

	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

 	json_test_manager manager(net_context, 0, remove_db);

	CHECK_JSON(manager.create_account(json_create_account("test")), json_create_account_result("test"));
	CHECK_JSON(manager.get_account(), json_get_account_result("test"));

	json_create_chat_result cc_res = manager.create_chat(json_create_chat("test chat", {}));
	REQUIRE(!cc_res.result.id.empty());
	std::string cid = cc_res.result.id;

	WAIT_CHECK(manager.has_create_event(cid), 2s);

	std::vector<json_message> messages;
	for(int i = 0; i != 10; ++i) {
		std::string m = print("%", i);
		json_send_message_result res = manager.send_message(json_send_message(cid, m));
		REQUIRE(!res.id.empty());
		messages.push_back(json_message{i+1, res.id, m, net_context.key_id(0), true});
	}

	WAIT_CHECK_JSON(manager.get_messages(json_get_messages(cid))
		, json_get_messages_result(messages), 10s);

	WAIT_CHECK_JSON(manager.get_messages(json_get_messages(cid, 100))
		, json_get_messages_result(messages), 10s);

	WAIT_CHECK_JSON(manager.get_messages(json_get_messages(cid, 100, true))
		, json_get_messages_result(messages), 10s);

	WAIT_CHECK_JSON(manager.get_messages(json_get_messages(cid, 100, false))
		, json_get_messages_result(messages), 10s);


	for(int i = 10; i != 69; ++i) {
		std::string m = print("%", i);
		json_send_message_result res = manager.send_message(json_send_message(cid, m));
		REQUIRE(!res.id.empty());
		messages.push_back(json_message{i+1, res.id, m, net_context.key_id(0), true});
	}
	WAIT_CHECK_JSON(manager.get_messages(json_get_messages(cid))
		, json_get_messages_result(messages), 10s);

	manager.disconnect();
	WAIT_CHECK(manager.has_disconnect_event(), 2s);

	for(int i = 69; i != 81; ++i) {
		std::string m = print("%", i);
		json_send_message_result res = manager.send_message(json_send_message(cid, m));
		REQUIRE(!res.id.empty());
		messages.push_back(json_message{i+1, res.id, m, net_context.key_id(0), true});
	}

	SECTION("desc chunking") {
		int total_amount = messages.size();
		std::size_t chuck_size = GENERATE(2, 12, 33);
		while(total_amount > 0) {
			auto list = list_messages(manager.get_messages(json_get_messages_chuck(cid, total_amount, chuck_size)));
			REQUIRE(list.size() <= total_amount);
			REQUIRE((list.size() == total_amount || list.size() == chuck_size));
			for(int i = 0; i != list.size(); ++i) {
				auto v = total_amount-i;
				REQUIRE(list[i].message == std::to_string(v-1));
				REQUIRE(list[i].index == v);
				CHECK(list[i] == messages[v-1]);
			}
			total_amount -= list.size();
		}
	}

	SECTION("asc chunking") {
		int total_amount = messages.size();
		std::size_t chuck_size = GENERATE(2, 12, 33);
		while(total_amount > 0) {
			auto list = list_messages(manager.get_messages(json_get_messages_chuck(cid, messages.size()-total_amount+1, chuck_size, false)));
			REQUIRE(list.size() <= total_amount);
			REQUIRE((list.size() == total_amount || list.size() == chuck_size));
			for(int i = 0; i != list.size(); ++i) {
				auto v = messages.size()-total_amount+i;
				REQUIRE(list[i].message == std::to_string(v));
				REQUIRE(list[i].index == v+1);
				CHECK(list[i] == messages[v]);
			}
			total_amount -= list.size();
		}
	}
}


TEST_CASE("json_manager requests test", "[system]") {

	sync::test::test_context net_context;
	net_context.add_client(2);

	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	{
		json_test_manager manager1(net_context, 0, remove_db);
		json_test_manager manager2(net_context, 1, remove_db);
		CHECK_JSON(manager1.create_account(json_create_account("test1")), json_create_account_result("test1"));
		CHECK_JSON(manager2.create_account(json_create_account("test2")), json_create_account_result("test2"));

		CHECK_EQUAL_JSON(manager1.connect(), "{}");
		CHECK_EQUAL_JSON(manager2.connect(), "{}");

		CHECK_JSON(manager1.add_contact(json_add_contact({"my test contact", net_context.key_id(1)}, "msg1"))
			, json_add_contact_result({"my test contact", net_context.key_id(1)}));
		CHECK_JSON(manager1.get_contacts(""), json_get_contacts_result({json_contact{"my test contact", net_context.key_id(1)}}));

		WAIT_CHECK(manager2.has_contacting_event("waiting_for_verification", net_context.key_id(0), "test1", "msg1"), 2s);
		CHECK_JSON(manager2.get_contacts(""), json_get_contacts_result({}));
		WAIT_CHECK(manager2.has_contacting_event("verification_succeeded", net_context.key_id(0), "test1", "msg1"), 2s);

		CHECK_JSON(manager2.get_requests(""), json_get_requests_result({
			json_request{
				1,
				net_context.key_id(0),
				"verification_succeeded",
				"test1",
				"msg1",
				"contacting"
			}}));

		auto rlist = list_requests(manager2.get_requests(""));
		REQUIRE(rlist.size() == 1);

		CHECK_JSON(manager2.request_action(json_request_action(1, "add_contact"))
			, json_add_contact_result({"test1", net_context.key_id(0)}));

		CHECK_JSON(manager2.get_contacts(""), json_get_contacts_result({json_contact{"test1", net_context.key_id(0)}}));
		{
			auto rlist = list_requests(manager2.get_requests(""));
			CHECK(rlist.size() == 0);
		}

		// chat invitation
		json_create_chat_result cc_res = manager1.create_chat(json_create_chat("test chat", {net_context.key_id(0), net_context.key_id(1)}));
		REQUIRE(!cc_res.result.id.empty());
		std::string cid = cc_res.result.id;

		CHECK_JSON(manager1.get_chats(""), json_get_chats_result({{"test chat", cid}}));

		WAIT_CHECK(manager2.has_invitation_event(net_context.key_id(0), "test1", ""), 2s);

		CHECK_JSON(manager2.get_requests(""), json_get_requests_result({
			json_request{
				1,
				net_context.key_id(0),
				"verification_succeeded",
				"test1",
				"",
				"invitation"
			}}));

		auto rlist2 = list_requests(manager2.get_requests(""));
		REQUIRE(rlist2.size() == 1);

		json_create_chat_result jres = manager2.request_action(json_request_action(1, "join"));
		REQUIRE(!cc_res.result.id.empty());
		CHECK(jres.result.name == "test chat");
		CHECK(jres.result.id == cid);
		CHECK_JSON(manager2.get_chats(""), json_get_chats_result({{"test chat", cid}}));
		{
			auto rlist = list_requests(manager2.get_requests(""));
			CHECK(rlist.size() == 0);
		}
	}
}

TEST_CASE("json_manager config test", "[system]") {

	sync::test::test_context net_context;
	net_context.add_client(1);

	sync::spsync_server_params params;
	params.key_params.timeout = 60s;
	sync::test::test_server server(net_context.server_context(), params);
	server.run();
	std::this_thread::sleep_for(1s);

	json_test_manager manager(net_context, 0, remove_db);
	CHECK(manager.set_config(R"({"network.timeout": 60})") == "{}");
	CHECK_JSON(manager.get_config(R"(["network.timeout"])"), R"({"network.timeout": 60})");
	CHECK_JSON(manager.create_account(json_create_account("test")), json_create_account_result("test"));
}

// every json call runs on the manager's event loop; from the event callback (already on
// the loop) it runs inline instead of waiting for itself
TEST_CASE("json_manager api from the event callback", "[system]") {
	sync::test::test_context net_context;
	net_context.add_client(1);
	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);
	std::filesystem::remove_all("client_9");

	std::promise<std::string> from_callback;
	std::once_flag once;
	json_manager* self{};
	json_manager manager(net_context.client_context(0), [&](auto, std::string) {
		std::call_once(once, [&] { from_callback.set_value(self->get_account()); });
	}, "client_9");
	self = &manager;

	// without an account there is nothing to connect: an error, not an assert
	CHECK(manager.connect().find("\"error\"") != std::string::npos);
	CHECK_JSON(manager.create_account(json_create_account("test")), json_create_account_result("test"));
	// the packet server connect reports through the callback, on the loop thread
	CHECK_EQUAL_JSON(manager.connect(), "{}");
	auto f = from_callback.get_future();
	REQUIRE(f.wait_for(5s) == std::future_status::ready);
	CHECK_EQUAL_JSON(f.get(), json_get_account_result("test"));
}

}
