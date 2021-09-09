#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/client_sync.hpp>
#include <spsync/client/record_util.hpp>

#include <spsync/test/util.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/test/test_progress.hpp>
#include <spsync/test/test_server_runner.hpp>


namespace securepath::sync::test {
namespace {
class test_client : public client_sync, public event_system::event_handler {
public:
	test_client(event_system::event_loop& loop, network::context& context, std::string const& dbname)
	: client_sync(loop, create_test_database(dbname))
	, event_handler(loop)
	, net(context, *this)
	{}

	~test_client() {
		client_sync::stop_handler();
		event_handler::stop_handler();
	}

	void connect() {
		net.connect("127.0.0.1", default_storage_server_port);
	}

	void disconnect() {
		net.close();
	}

	storage_id create_remote_storage() {
		return net.create_storage();
	}

	void connect_to_storage(storage_id const& sid) {
		assert(!sid.empty());

		//after this the events will be received
		init(sid, net);
	}

	void wait_for_connection() {
		connected_.get_future().get();
	}

	void on_connect() {
		try {
			connected_.set_value();
		} catch(...) {}
	}

	void on_disconnect(error const& err) {
		try {
			connected_.set_exception(std::make_exception_ptr(err));
		} catch(...) {}
	}

	void on_create_storage(storage_id const& sid, error const& err) {
		if(err) {
			storage_created_.set_exception(std::make_exception_ptr(err));
		} else {
			connect_to_storage(sid);
			storage_created_.set_value();
		}
	}

	void wait_for_storage_created() {
		storage_created_.get_future().get();
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<events::on_connect>(&test_client::on_connect)
				, event_dest<events::on_disconnect>(&test_client::on_disconnect)
				, event_dest<events::on_create_storage>(&test_client::on_create_storage) );
	}


	void on_data_change(record_handle, std::deque<single_data_change> c) override {
		std::unique_lock l{mutex};
		d_changes.insert(d_changes.end(), c.begin(), c.end());
	}

	void on_user_change(record_handle, user_change c) override {
		std::unique_lock l{mutex};
		u_changes.push_back(c);
	}

	std::deque<single_data_change> data_changes() const {
		std::unique_lock l{mutex};
		return d_changes;
	}

	std::deque<user_change> user_changes() const {
		std::unique_lock l{mutex};
		return u_changes;
	}

public:
	network_connection net;
	mutable std::mutex mutex;
	std::deque<single_data_change> d_changes;
	std::deque<user_change> u_changes;

private:
	std::promise<void> connected_;
	std::promise<void> storage_created_;
};

bool check_member_status(test_client const& c, crypto::public_key_id const& uid, member_status status) {
	auto m = c.find(util::user_id{uid});
	REQUIRE(m);
	CHECK(m->status() == status);
	return m->status() == status;
}
}

TEST_CASE("client_sync", "[unit]") {
	event_system::single_thread_event_loop single_thread_event_loop;
	test_context net_context;

	net_context.add_client(4);
	net_context.add_client_keys_for_server();
	net_context.share_client_keys();

	test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	test_client c1(single_thread_event_loop, net_context.client_context(0), "client_sync_c1.db");
	test_client c2(single_thread_event_loop, net_context.client_context(1), "client_sync_c2.db");

	c1.connect();
	c2.connect();
	c1.wait_for_connection();
	auto sid = c1.create_remote_storage();
	c1.wait_for_storage_created();
	c2.wait_for_connection();
	c2.connect_to_storage(sid);

	users us(users_change_mode::full);
	us.add(util::user_access{net_context.key_id(0), util::access_type::user_management_access});
	us.add(util::user_access{net_context.key_id(1), util::access_type::user_management_access});
	c1.send_user_change(us);

	WAIT_CHECK(c1.user_changes().size() == 1, 2s);
	WAIT_CHECK(c2.user_changes().size() == 1, 2s);

	// check initial members
	{
		auto m = c1.members();
		CHECK(m.size() == 2);
		CHECK(check_member_status(c1, net_context.key_id(0), member_status::member));
		CHECK(check_member_status(c1, net_context.key_id(1), member_status::member));
	}
	{
		auto m = c2.members();
		CHECK(m.size() == 2);
		CHECK(check_member_status(c2, net_context.key_id(0), member_status::member));
		CHECK(check_member_status(c2, net_context.key_id(1), member_status::member));
	}

	// add members
	c1.add(util::user_id{net_context.key_id(2)});
	c2.add(util::user_id{net_context.key_id(3)});

	{
		WAIT_CHECK(c1.user_changes().size() == 3, 2s);
		auto m = c1.members();
		CHECK(m.size() == 4);
		for(int i = 0; i != 4; ++i) {
			CHECK(check_member_status(c1, net_context.key_id(i), member_status::member));
		}
	}
	{
		WAIT_CHECK(c2.user_changes().size() == 3, 2s);
		auto m = c2.members();
		CHECK(m.size() == 4);
		for(int i = 0; i != 4; ++i) {
			CHECK(check_member_status(c2, net_context.key_id(i), member_status::member));
		}
	}

	// remove members
	c1.remove(util::user_id{net_context.key_id(2)});
	c2.remove(util::user_id{net_context.key_id(3)});

	{
		WAIT_CHECK(c1.user_changes().size() == 5, 2s);
		auto m = c1.members();
		CHECK(m.size() == 2);
		CHECK(check_member_status(c1, net_context.key_id(0), member_status::member));
		CHECK(check_member_status(c1, net_context.key_id(1), member_status::member));
	}
	{
		WAIT_CHECK(c2.user_changes().size() == 5, 2s);
		auto m = c2.members();
		CHECK(m.size() == 2);
		CHECK(check_member_status(c2, net_context.key_id(0), member_status::member));
		CHECK(check_member_status(c2, net_context.key_id(1), member_status::member));
	}

	// pending add members
	c1.disconnect();
	c1.add(util::user_id{net_context.key_id(2)});

	{
		auto m = c1.members();
		CHECK(m.size() == 3);
		CHECK(check_member_status(c1, net_context.key_id(0), member_status::member));
		CHECK(check_member_status(c1, net_context.key_id(1), member_status::member));
		CHECK(check_member_status(c1, net_context.key_id(2), member_status::pending_add));
	}

	// pending remove members
	c2.disconnect();
	c2.remove(util::user_id{net_context.key_id(1)});

	{
		auto m = c2.members();
		CHECK(m.size() == 2);
		CHECK(check_member_status(c2, net_context.key_id(0), member_status::member));
		CHECK(check_member_status(c2, net_context.key_id(1), member_status::pending_remove));
	}

	c1.connect();
	c2.connect();

	{
		WAIT_CHECK(c1.user_changes().size() == 7, 2s);
		auto m = c1.members();
		CHECK(m.size() == 2);
		CHECK(check_member_status(c1, net_context.key_id(0), member_status::member));
		CHECK(check_member_status(c1, net_context.key_id(2), member_status::member));
	}
	{
		WAIT_CHECK(c2.user_changes().size() == 7, 2s);
		auto m = c2.members();
		CHECK(m.size() == 2);
		CHECK(check_member_status(c2, net_context.key_id(0), member_status::member));
		CHECK(check_member_status(c2, net_context.key_id(2), member_status::member));
	}
}

}