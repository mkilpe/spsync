#include "handler_test_client.hpp"

namespace securepath::sync::client::test {


TEST_CASE("contact_handler test", "[unit]") {
	event_system::single_thread_event_loop single_thread_event_loop;
	sync::test::test_context net_context;

	net_context.add_client(2);
	net_context.add_client_keys_for_server();

	user user1{net_context.key_id(0), local_key_server};
	user user2{net_context.key_id(1), local_key_server};

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

	auto c = c1.conn.add_contact(user2, "user2", "test message");
	CHECK(c->id() == net_context.key_id(1));
	CHECK(c->server() == local_key_server);
	CHECK(c->state() == contact_state::complete);
	CHECK(c->name() == "user2");
	CHECK(c1.conn.contacts().find(net_context.key_id(1)));

	WAIT_CHECK(c2.has_contacting(request_state::waiting_for_verification, user1, "test", "test message"), 2s);
	WAIT_CHECK(c2.has_contacting(request_state::verification_succeeded, user1, "test", "test message"), 2s);

	auto list = c2.conn.requests().enumerate();
	REQUIRE(list.size() == 1);

	c2.conn.accept_contact_request(list.front().id);

	auto new_c = c2.conn.contacts().find(net_context.key_id(0));
	REQUIRE(new_c);
	CHECK(new_c->state() == contact_state::complete);
	CHECK(new_c->id() == net_context.key_id(0));
	CHECK(new_c->server() == local_key_server);
	CHECK(new_c->name() == "test");

	CHECK(c2.conn.requests().enumerate().size() == 0);

	// try sending again, no event should come when already contact
	c2.clear_requests();
	c1.conn.add_contact(user2, "user2", "test message");
	WAIT(c2.requests_size(), 2s);
	CHECK(!c2.has_contacting(request_state::verification_succeeded, user1, "test", "test message"));

	storage_info sinfo{
		securepath::test::random_octet_vector(4),
		local_key_server,
		local_packet_server,
		chain_block_id{sequence_number{1}, securepath::test::random_octet_vector(32)},
		{encryption_key{sequence_number{1}, securepath::test::random_octet_vector(32)}} };

	c1.conn.send_storage_invitation(user2, "test invite", "my storage", sinfo);
	WAIT_CHECK(c2.has_storage_invitation(request_state::verification_succeeded, user1, "test invite", "my storage", sinfo), 2s);
}

}