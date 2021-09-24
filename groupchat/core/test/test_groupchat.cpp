#include <groupchat/core/groupchat.hpp>
#include <groupchat/core/events.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/test/test_server_runner.hpp>
#include <securepath/network/test/support/testing_context.hpp>


namespace securepath::groupchat::test {

using namespace securepath::sync;

class test_groupchat : public event_system::event_handler, public groupchat {
public:
	test_groupchat(network::context& context, event_system::event_loop& loop)
	: event_handler(loop)
	, groupchat(*this, context, groupchat_config{})
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
	void on_create(server_id, chat_id id, error err) {
		if(err) {
			created.set_exception(std::make_exception_ptr(err));
		} else {
			created.set_value(id);
		}

	}
	/// called when user changed or failed
	void on_change_user(server_id, chat_id, sync::users change, error) {
	}
	/// called when chat joined or it failed
	void on_join(server_id, chat_id, error) {
	}
	/// called when chat message received
	void on_message(server_id, chat_id id, message m) {
	}


	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		namespace gc_ev = securepath::groupchat::events;
		dispatch( *ev
			, event_dest<gc_ev::on_connect>(&test_groupchat::on_connect)
			, event_dest<gc_ev::on_disconnect>(&test_groupchat::on_disconnect)
			, event_dest<gc_ev::on_create>(&test_groupchat::on_create)
			, event_dest<gc_ev::on_change_user>(&test_groupchat::on_change_user)
			, event_dest<gc_ev::on_join>(&test_groupchat::on_join)
			, event_dest<gc_ev::on_message>(&test_groupchat::on_message) );
	}


	std::promise<error> connected;
	std::promise<chat_id> created;
};

TEST_CASE("groupchat_test", "[system]") {
	std::remove(groupchat_config{}.db().c_str());

	network::test::testing_context net_context;
	net_context.set_server_dh_parameters();
	net_context.set_server_pk_parameters();
	net_context.set_client_dh_parameters();
	net_context.set_client_pk_parameters();

	//add client key to the db
	//net_context.keys.insert(my_private_key(net_context.client_private_data).public_key());

	sync::test::test_server server(net_context.server_context);
	server.run();
	std::this_thread::sleep_for(1s);

	chat_id cid;

	host_port hp{"127.0.0.1", sync::default_storage_server_port};
	event_system::single_thread_event_loop loop;
	{
		test_groupchat client(net_context.client_context, loop);

		CHECK(!client.account_info());

		client.create_account(hp, "test");

		auto info = client.account_info();
		REQUIRE(info);
		CHECK(info->server == hp);
		CHECK(info->name == "test");
		CHECK(info->key_id.is_valid());

		auto conn = client.load(hp);

		conn->connect();
		{
			auto f = client.connected.get_future();
			WAIT_CHECK(f.valid(), 2s);
			REQUIRE(f.valid());
			REQUIRE(!f.get());
		}

		cid = conn->create_chat("test").id();
		{
			auto f = client.created.get_future();
			WAIT_CHECK(f.valid(), 2s);
			REQUIRE(f.valid());
			REQUIRE(f.get() == cid);
			CHECK(client.channel_ids().find_server(cid));
		}
	}
	{
		test_groupchat client(net_context.client_context, loop);

		auto info = client.account_info();
		REQUIRE(info);
		CHECK(info->server == hp);
		CHECK(info->name == "test");
		CHECK(info->key_id.is_valid());
		CHECK(client.channel_ids().find_server(cid));

		auto ids = client.load_channels();
		CHECK(ids.size() == 1);
		//t: implement rest
	}
}

}