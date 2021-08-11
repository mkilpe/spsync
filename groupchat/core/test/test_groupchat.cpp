#include <groupchat/core/groupchat.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/test/test_server_runner.hpp>
#include <securepath/network/test/support/testing_context.hpp>


namespace securepath::groupchat::test {

/*
/// connect to storage server
	server_id connect(std::string_view server, std::uint16_t port);

	/// disconnect from server
	void disconnect(server_id);

	/// Create chat on given server, will call on_create when fail or succeed
	chat_id create_chat(server_id);

	/// change users for chat
	void change_user(server_id const& server, chat_id const& storage, sync::users change);

	/// join existing chat
	void join(server_id const& server, chat_id const& storage);

	/// Send a message to the chat
	message_id send_message(server_id const& server, chat_id const& chat, std::string const& message);
*/
using namespace securepath::sync;

class test_groupchat : public groupchat {
public:
	test_groupchat(network::context& context, event_system::event_loop& loop)
	: groupchat(context, groupchat_config{}, loop)
	{}

	/// called when server connected
	void on_connect(server_id) override {
		connected.set_value(error{});
	}
	/// called when server disconnected
	void on_disconnect(server_id, error err) override {
		connected.set_value(err);
	}
	/// called when chat created or creating failed
	void on_create(server_id, chat_id id, error err) override {
		created.set_value(err ? chat_id{} : id);
	}
	/// called when user changed or failed
	void on_change_user(server_id, chat_id, sync::users change, error) override {
	}
	/// called when chat joined or it failed
	void on_join(server_id, chat_id) override {
	}
	/// called when chat message received
	void on_message(server_id, chat_id id, message m) override {
	}

	std::promise<error> connected;
	std::promise<chat_id> created;
};

TEST_CASE("groupchat_test", "[system]") {
	network::test::testing_context net_context;
	net_context.set_server_dh_parameters();
	net_context.set_server_pk_parameters();
	net_context.set_client_dh_parameters();
	net_context.set_client_pk_parameters();

	//add client key to the db
	net_context.keys.insert(my_private_key(net_context.client_private_data).public_key());

	sync::test::test_server server(net_context.server_context);
	server.run();
	std::this_thread::sleep_for(1s);

	event_system::single_thread_event_loop loop;
	test_groupchat client(net_context.client_context, loop);

	auto server_id = client.connect("127.0.0.1", sync::default_storage_server_port);
	{
		auto f = client.connected.get_future();
		WAIT_CHECK(f.valid(), 2s);
		REQUIRE(f.valid());
		REQUIRE(!f.get());
	}

	auto cid = client.create_chat(server_id, L"test");
	{
		auto f = client.created.get_future();
		WAIT_CHECK(f.valid(), 2s);
		REQUIRE(f.valid());
		REQUIRE(f.get() == cid);
	}
}

}