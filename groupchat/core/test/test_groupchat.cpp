#include <groupchat/core/groupchat.hpp>
#include <groupchat/core/events.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/events.hpp>
#include <spsync/test/test_server_runner.hpp>
#include <spsync/test/test_context.hpp>

#include <filesystem>
#include <set>

namespace securepath::groupchat::test {

using namespace securepath::sync;

class test_groupchat : public event_system::event_handler, public groupchat {
public:
	test_groupchat(network::context& context, event_system::event_loop& loop, groupchat_config config = {})
	: event_handler(loop)
	, groupchat(*this, context, std::move(config))
	{}

	~test_groupchat() {
		stop_handler();
	}

	/// called when server connected
	void on_connect(server_id) {
		connected.set_value(error{});
	}
	/// called when server disconnected
	void on_disconnect(server_id, error err) {
		connected.set_value(err);
	}
	/// called when chat created or creating failed
	void on_create(server_chat_id id, sync::users change, error err) {
		if(err) {
			created.set_exception(std::make_exception_ptr(err));
		} else {
			created.set_value(id.cid);
		}

	}
	/// called when user changed or failed
	void on_change_user(server_chat_id id, sync::users change, error) {
	}

	/// called when chat joined or it failed
	void on_join(server_chat_id id, sync::users, error err) {
		if(err) {
			joined.set_exception(std::make_exception_ptr(err));
		} else {
			joined.set_value(id.cid);
		}

	}
	/// called when chat message received (own committed messages included)
	void on_message(server_chat_id id, msg_data md, msg_change change) {
		std::unique_lock l{mutex};
		received.insert(md.message);
	}

	/// called when the packet server connection is up
	void on_packet_connect() {
		try { packet_connected.set_value(); } catch(...) {}
	}

	void on_packet_disconnect(error) {
	}

	/// called when a chat invitation arrives (fires again after verification, hence the guard)
	void on_invitation(sync::client::request req, sync::client::storage_info, std::string, std::string) {
		try { invitation.set_value(req.id); } catch(...) {}
	}

	bool has_message(std::string const& m) {
		std::unique_lock l{mutex};
		return received.count(m) != 0;
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		namespace gc_ev = securepath::groupchat::events;
		dispatch( *ev
			, event_dest<gc_ev::on_connect>(&test_groupchat::on_connect)
			, event_dest<gc_ev::on_disconnect>(&test_groupchat::on_disconnect)
			, event_dest<gc_ev::on_create>(&test_groupchat::on_create)
			, event_dest<gc_ev::on_change_user>(&test_groupchat::on_change_user)
			, event_dest<gc_ev::on_join>(&test_groupchat::on_join)
			, event_dest<gc_ev::on_message>(&test_groupchat::on_message)
			, event_dest<sync::client::events::on_connect>(&test_groupchat::on_packet_connect)
			, event_dest<sync::client::events::on_disconnect>(&test_groupchat::on_packet_disconnect)
			, event_dest<sync::client::events::on_invitation>(&test_groupchat::on_invitation) );
	}


	std::promise<error> connected;
	std::promise<chat_id> created;
	std::promise<chat_id> joined;
	std::promise<void> packet_connected;
	std::promise<sync::client::request_id> invitation;
	std::mutex mutex;
	std::set<std::string> received;
};

TEST_CASE("groupchat_test", "[system]") {
	std::remove(groupchat_config{}.db().c_str());

	sync::test::test_context net_context;
	net_context.add_client(3);

	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	chat_id cid;

	gc_servers hp{"127.0.0.1", sync::default_key_server_port, sync::default_storage_server_port, packet_transport::default_packet_server_port};
	event_system::single_thread_event_loop loop;
	{
		test_groupchat client(net_context.client_context(0), loop);

		CHECK(!client.account_info());

		client.create_account(hp, "test");

		auto info = client.account_info();
		REQUIRE(info);
		CHECK(info->server == hp.sync_server());
		CHECK(info->name == "test");
		CHECK(info->me.is_valid());

		auto conn = client.load(hp.sync_server());

		conn->connect();
		{
			auto f = client.connected.get_future();
			REQUIRE(f.wait_for(2s) == std::future_status::ready);
			REQUIRE(!f.get());
		}

		cid = conn->create_chat("test").id();
		{
			auto f = client.created.get_future();
			REQUIRE(f.wait_for(2s) == std::future_status::ready);
			REQUIRE(f.get() == cid);
			CHECK(client.channel_ids().find_server(cid));
		}
	}
	{
		test_groupchat client(net_context.client_context(0), loop);

		auto info = client.account_info();
		REQUIRE(info);
		CHECK(info->server == hp.sync_server());
		CHECK(info->name == "test");
		CHECK(info->me.is_valid());
		CHECK(client.channel_ids().find_server(cid));

		auto ids = client.load_channels();
		CHECK(ids.size() == 1);
		//t: implement rest
	}
}


// two accounts: create a chat, invite over the packet server, join from the invitation
// request, message both ways and reload the joiner from disk
TEST_CASE("groupchat invite join message test", "[system]") {
	std::filesystem::remove_all("gc_test_c0");
	std::filesystem::remove_all("gc_test_c1");
	std::filesystem::create_directories("gc_test_c0");
	std::filesystem::create_directories("gc_test_c1");

	sync::test::test_context net_context;
	net_context.add_client(2);

	sync::test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	gc_servers hp{"127.0.0.1", sync::default_key_server_port, sync::default_storage_server_port, packet_transport::default_packet_server_port};
	event_system::single_thread_event_loop loop;

	test_groupchat alice(net_context.client_context(0), loop, groupchat_config{"gc_test_c0"});
	alice.create_account(hp, "alice");
	alice.connect();
	REQUIRE(alice.packet_connected.get_future().wait_for(5s) == std::future_status::ready);

	auto conn0 = alice.load(hp.sync_server());
	conn0->connect().get();

	chat_id cid = conn0->create_chat("room").id();
	{
		auto f = alice.created.get_future();
		REQUIRE(f.wait_for(5s) == std::future_status::ready);
		REQUIRE(f.get() == cid);
	}

	{
		test_groupchat bob(net_context.client_context(1), loop, groupchat_config{"gc_test_c1"});
		bob.create_account(hp, "bob");
		bob.connect();
		REQUIRE(bob.packet_connected.get_future().wait_for(5s) == std::future_status::ready);

		// the invitation travels through the packet server; bob's key is fetched from
		// the key server by alice's request handler
		alice.send_chat_invitation(user{user_id{net_context.key_id(1)}, hp.key_server()}, "join us", cid);

		auto inv = bob.invitation.get_future();
		REQUIRE(inv.wait_for(5s) == std::future_status::ready);

		// join_chat loads the chat connection but does not connect it (the json layer
		// does the same dance); connect it first so the join actually synchronises
		auto conn1 = bob.load(hp.sync_server());
		conn1->connect().get();
		auto info = bob.join_chat(inv.get());
		CHECK(info.cid == cid);
		{
			auto f = bob.joined.get_future();
			REQUIRE(f.wait_for(5s) == std::future_status::ready);
			REQUIRE(f.get() == cid);
		}

		auto& chan0 = conn0->get(cid);
		auto& chan1 = conn1->get(cid);

		chan0.send_message("hello from alice");
		chan1.send_message("hello from bob");

		WAIT_CHECK(alice.has_message("hello from bob"), 5s);
		WAIT_CHECK(bob.has_message("hello from alice"), 5s);
		WAIT_CHECK(chan0.messages().size() == 2, 5s);
		WAIT_CHECK(chan1.messages().size() == 2, 5s);
	}

	// bob reloads from disk: the channel and both messages are still there
	{
		test_groupchat bob(net_context.client_context(1), loop, groupchat_config{"gc_test_c1"});
		REQUIRE(bob.account_info());
		CHECK(bob.account_info()->name == "bob");
		auto ids = bob.load_channels();
		REQUIRE(ids.size() == 1);
		CHECK(ids.front().cid == cid);
		auto conn1 = bob.load(hp.sync_server());
		CHECK(conn1->get(cid).messages().size() == 2);
	}
}

}