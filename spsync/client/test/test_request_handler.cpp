#include "handler_test_client.hpp"

namespace securepath::sync::client::test {

TEST_CASE("request handler test", "[unit]") {
	event_system::single_thread_event_loop single_thread_event_loop;
	sync::test::test_context net_context;
	sync::test::test_context dummy_server_context(net_context.root_key());

	net_context.add_client(4);
	net_context.add_client_keys_for_server();

	user user1{net_context.key_id(0), local_key_server};
	user user2{net_context.key_id(1), local_key_server};
	user user3{net_context.key_id(2), local_key_server};
	user user4{net_context.key_id(3), local_key_server};

	// key not found but server responses
	host_port bad_host1{"127.0.0.1", sync::default_key_server_port+10};
	host_port bad_host2{"127.0.0.1", sync::default_key_server_port+20};

	user bad_host1_user{net_context.key_id(3), bad_host1};
	user bad_host2_user{net_context.key_id(3), bad_host2};

	sync::test::test_server server(net_context.server_context());
	server.run();

	std::this_thread::sleep_for(1s);

	test_client c1(single_thread_event_loop, net_context.client_context(0), "rh_test_c1.db");
	test_client c2(single_thread_event_loop, net_context.client_context(1), "rh_test_c2.db");

	c1.connect();
	c2.connect();

	c1.wait_for_connect();
	c2.wait_for_connect();

	octet_vector tdata = securepath::test::random_octet_vector(256);

	SECTION("simple success") {
		c1.conn.send_request(user2, "test tag", tdata);

		WAIT_CHECK(c2.has_request(request_state::waiting_for_verification, user1, "test tag", tdata), 2s);
		WAIT_CHECK(c2.has_request(request_state::verification_succeeded, user1, "test tag", tdata), 2s);

		CHECK(c2.storage_has(request_state::verification_succeeded, user1, "test tag", tdata));
	}
	SECTION("key query fail 1") {
		key_server::unknown_user_key_server dummy_key_server(
			dummy_server_context.server_context(),
			key_server::unknown_user_key_server_params{.port=sync::default_key_server_port+10});

		dummy_key_server.run();

		test_client bad(single_thread_event_loop, net_context.client_context(3), "rh_test_c4.db", bad_host1);
		bad.connect();
		bad.wait_for_connect();

		bad.conn.send_request(user1, "test tag", tdata);
		WAIT_CHECK(c1.has_request(request_state::waiting_for_verification, bad_host1_user, "test tag", tdata), 2s);
		WAIT_CHECK(c1.has_request(request_state::no_key_found, bad_host1_user, "test tag", tdata), 2s);

		CHECK(c1.storage_has(request_state::no_key_found, bad_host1_user, "test tag", tdata));

		dummy_server_context.server_context().public_keys().insert(
			my_private_key(net_context.client_context(3).private_data()).public_key());

		auto list = c1.conn.requests().enumerate();
		REQUIRE(list.size() == 1);

		c1.conn.try_evaluate_request(list.front().id);

		WAIT_CHECK(c1.has_request(request_state::verification_succeeded, bad_host1_user, "test tag", tdata), 2s);
		CHECK(c1.storage_has(request_state::verification_succeeded, user1, "test tag", tdata));
	}
	SECTION("key query fail 2") {
		test_client bad(single_thread_event_loop, net_context.client_context(3), "rh_test_c4.db", bad_host2);
		bad.connect();
		bad.wait_for_connect();

		bad.conn.send_request(user1, "test tag", tdata);
		WAIT_CHECK(c1.has_request(request_state::waiting_for_verification, bad_host2_user, "test tag", tdata), 2s);
		WAIT_CHECK(c1.has_request(request_state::querying_key_failed, bad_host2_user, "test tag", tdata), 2s);

		CHECK(c1.storage_has(request_state::querying_key_failed, bad_host2_user, "test tag", tdata));
	}
	SECTION("restart test") {
		{
			test_client bad(single_thread_event_loop, net_context.client_context(3), "rh_test_c4.db", bad_host1);
			test_client c3(single_thread_event_loop, net_context.client_context(2), "rh_test_c3.db");
			bad.connect();
			c3.connect();
			bad.wait_for_connect();
			c3.wait_for_connect();

			bad.conn.send_request(user3, "test tag", tdata);
			WAIT_CHECK(c3.has_request(request_state::waiting_for_verification, bad_host1_user, "test tag", tdata), 2s);
			WAIT_CHECK(c3.has_request(request_state::querying_key_failed, bad_host1_user, "test tag", tdata), 2s);

			CHECK(c3.storage_has(request_state::querying_key_failed, bad_host1_user, "test tag", tdata));
		}
		LOG_TRACE("restarting test_client");
		{
			key_server::unknown_user_key_server dummy_key_server(
				dummy_server_context.server_context(),
				key_server::unknown_user_key_server_params{.port=sync::default_key_server_port+10});

			dummy_server_context.server_context().public_keys().insert(
				my_private_key(net_context.client_context(3).private_data()).public_key());

			dummy_key_server.run();

			test_client c3(keep_db, single_thread_event_loop, net_context.client_context(2), "rh_test_c3.db");
			c3.conn.emit_pending_requests();

			WAIT_CHECK(c3.has_request(request_state::verification_succeeded, bad_host1_user, "test tag", tdata), 2s);
			CHECK(c3.storage_has(request_state::verification_succeeded, bad_host1_user, "test tag", tdata));
		}
	}
}

}