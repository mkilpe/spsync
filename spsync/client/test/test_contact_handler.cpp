// SPDX-License-Identifier: MIT

#include "handler_test_client.hpp"

namespace securepath::sync::client::test {
namespace {

/// the context with two clients whose keys the server knows
sync::test::test_context& with_two_clients(sync::test::test_context& ctx) {
	ctx.add_client(2);
	ctx.add_client_keys_for_server();
	return ctx;
}

/// two clients connected to a test server, each one the other's would-be contact
struct two_clients {
	two_clients()
	: server(with_two_clients(net_context).server_context())
	, c1(single_thread_event_loop, net_context.client_context(0), "rh_test_c1.db")
	, c2(single_thread_event_loop, net_context.client_context(1), "rh_test_c2.db")
	{
		server.run();
		c1.connect();
		c2.connect();
		c1.wait_for_connect();
		c2.wait_for_connect();
	}

public:
	event_system::single_thread_event_loop single_thread_event_loop;
	sync::test::test_context net_context;
	sync::test::test_server server;
	user user1{net_context.key_id(0), local_key_server};
	user user2{net_context.key_id(1), local_key_server};
	test_client c1;
	test_client c2;
};

/// the complete contact of the key at the local key server under the name
void check_contact(std::unique_ptr<contact> const& c, crypto::public_key_id const& id, std::string const& name) {
	REQUIRE(c);
	CHECK(c->id() == id);
	CHECK(c->server() == local_key_server);
	CHECK(c->state() == contact_state::complete);
	CHECK(c->name() == name);
}

}

TEST_CASE("contact_handler test", "[unit]") {
	two_clients f;
	auto& c1 = f.c1;
	auto& c2 = f.c2;

	octet_vector tdata = securepath::test::random_octet_vector(256);

	auto c = c1.conn.add_contact(f.user2, "user2", "test message");
	check_contact(c, f.net_context.key_id(1), "user2");
	CHECK(c1.conn.contacts().find(f.net_context.key_id(1)));

	WAIT_CHECK(c2.has_contacting(request_state::waiting_for_verification, f.user1, "test", "test message"), 2s);
	WAIT_CHECK(c2.has_contacting(request_state::verification_succeeded, f.user1, "test", "test message"), 2s);

	auto list = c2.conn.requests().enumerate();
	REQUIRE(list.size() == 1);

	c2.conn.accept_contact_request(list.front().id);

	check_contact(c2.conn.contacts().find(f.net_context.key_id(0)), f.net_context.key_id(0), "test");
	CHECK(c2.conn.requests().enumerate().size() == 0);

	// try sending again, no event should come when already contact
	c2.clear_requests();
	c1.conn.add_contact(f.user2, "user2", "test message");
	WAIT(c2.requests_size(), 2s);
	CHECK(!c2.has_contacting(request_state::verification_succeeded, f.user1, "test", "test message"));

	storage_info sinfo{
		securepath::test::random_octet_vector(4),
		local_key_server,
		local_packet_server,
		chain_block_id{sequence_number{1}, securepath::test::random_octet_vector(32)},
		{encryption_key{sequence_number{1}, securepath::test::random_octet_vector(32)}} };

	c1.conn.send_storage_invitation(f.user2, "test invite", "my storage", sinfo);
	WAIT_CHECK(c2.has_storage_invitation(request_state::verification_succeeded, f.user1, "test invite", "my storage", sinfo), 2s);
}

}
