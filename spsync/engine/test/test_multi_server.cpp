#include <spsync/test/test_sync_server.hpp>
#include <spsync/client/record_util.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <random>

namespace securepath::sync {
using namespace securepath::sync::util;

namespace {

/// three servers in a chain topology (0-1, 1-2: transitivity through the middle) with
/// clients_per_server clients on each (client i sits on server i % 3)
void setup_three(test::test_sync_context& context, int clients_per_server = 1) {
	context.set_trace(true);
	context.add_server("test_sync_server_b.db");
	context.add_server("test_sync_server_c.db");
	context.add_link(0, 1);
	context.add_link(1, 2);
	context.add_client(false, 3 * clients_per_server);
	for(int i = 0; i != 3 * clients_per_server; ++i) {
		context.connect_client_to(i, i % 3);
	}
	// every client knows every key so any of them can invite/remove others
	for(auto& c1 : context.clients) {
		for(auto& c2 : context.clients) {
			c1->pkeys.insert(c2->user_key.public_key());
		}
	}
	context.create_initial_record();
	while(context.handle_events()) {}
}

}

// (24) three replicas with clients on each (plan 4.7): commits spread transitively, a
// partition diverges and heals back to convergence
TEST_CASE("multi server converge and heal", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	setup_three(context);
	REQUIRE(context.servers_converged());

	// everyone commits; the middle server relays between the ends
	for(int i = 0; i != 3; ++i) {
		context.client(i).engine.sync_object_change(create_object_id(), metadata{});
	}
	while(context.handle_events()) {}
	CHECK(context.servers_converged());
	CHECK(context.server_n(0).sync.current_sequence_number() == sequence_number{4});
	CHECK(context.server_n(2).sync.current_sequence_number() == sequence_number{4});

	// partition server 0 away; both sides keep committing and diverge
	context.set_link(0, 1, false);
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.client(2).engine.sync_object_change(create_object_id(), metadata{});
	while(context.handle_events()) {}
	CHECK(!context.servers_converged());

	// heal: the rescan brings both sides together
	context.set_link(0, 1, true);
	while(context.handle_events()) {}
	CHECK(context.servers_converged());
	CHECK(context.server_n(0).sync.current_sequence_number() == sequence_number{6});

	// a link with delay still converges, just later
	context.set_link(1, 2, false);
	context.add_link(0, 2, 3);
	context.client(1).engine.sync_object_change(create_object_id(), metadata{});
	while(context.handle_events()) {}
	CHECK(context.servers_converged());

	// a client hops to another replica (the 4.5 resync) and keeps working there
	context.disconnect_client(0);
	while(context.handle_events()) {}
	context.connect_client_to(0, 2);
	while(context.handle_events()) {}
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	while(context.handle_events()) {}
	CHECK(context.servers_converged());
	CHECK(context.client(0).io.records().cursor_owner() == context.server_n(2).id.data());
	context.print_summary();
}

// (25) the full scenario (plan 4.7): three replicas, six clients (two each), exercising
// every record kind and event - data changes, membership changes, key rotation
// (including concurrent colliding rotations, D9), segment seals, partitions and clients
// hopping between replicas - each phase asserts convergence so a failure localises
TEST_CASE("multi server full scenario", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	setup_three(context, 2);   // clients 0,3 on server 0; 1,4 on server 1; 2,5 on server 2

	std::vector<int> const all_members{0, 1, 2, 3, 4, 5};
	auto drain = [&] { while(context.handle_events()) {} };

	// rotate the encryption key from `client`, distributing the fresh key to `members`
	auto rotate_key = [&](int client, std::vector<int> const& members) {
		auto& c = context.client(client);
		c.enc_keys.create_key();   // a fresh key becomes this client's current
		users delta{users_change_mode::delta};
		for(int m : members) {
			delta.add(util::user_access{context.client(m).user, util::access_type::data_write_access});
		}
		c.engine.sync_user_change(encrypt_last_key_for_users(delta, c.cc));
	};
	// seal a segment from `client` (needs its local commits flushed first, SEG 2)
	auto seal_segment = [&](int client) {
		drain();
		try {
			context.client(client).engine.sync_segment_end(metadata{});
		} catch(std::exception const& e) {
			LOG_INFO("segment not sealed: {}", e.what());
		}
		drain();
	};

	// phase 1: plain data changes from every client spread across the replicas
	for(int i : all_members) {
		context.client(i).engine.sync_object_change(create_object_id(), metadata{});
	}
	drain();
	REQUIRE(context.servers_converged());

	// phase 2: a membership change (add is a no-op re-affirm here; remove client 5)
	{
		auto& c = context.client(0);
		users delta{users_change_mode::delta};
		delta.remove(context.client(5).user);
		c.engine.sync_user_change(encrypt_last_key_for_users(delta, c.cc));
	}
	drain();
	REQUIRE(context.servers_converged());

	// phase 3: a key rotation, then data committed under the new key stays readable
	rotate_key(1, all_members);
	drain();
	for(int i : {0, 2, 4}) {
		context.client(i).engine.sync_object_change(create_object_id(), metadata{});
	}
	drain();
	REQUIRE(context.servers_converged());

	// phase 4: concurrent rotations on two clients -> two keys at one sequence (D9);
	// records committed under each remain readable everywhere
	rotate_key(0, all_members);
	rotate_key(2, all_members);
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.client(2).engine.sync_object_change(create_object_id(), metadata{});
	drain();
	REQUIRE(context.servers_converged());

	// phase 5: a segment seal, then more data on top of the sealed history
	seal_segment(3);
	REQUIRE(context.servers_converged());
	context.client(4).engine.sync_object_change(create_object_id(), metadata{});
	drain();
	REQUIRE(context.servers_converged());

	// phase 6: partition, commits on both sides (incl. a rotation), a client hop, heal
	context.set_link(0, 1, false);
	context.set_link(1, 2, false);   // isolate server 1
	rotate_key(0, all_members);
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.client(1).engine.sync_object_change(create_object_id(), metadata{});
	drain();
	CHECK(!context.servers_converged());

	// client 1 hops off the isolated server 1 onto server 2 and keeps working
	context.disconnect_client(1);
	drain();
	context.connect_client_to(1, 2);
	drain();
	context.client(1).engine.sync_object_change(create_object_id(), metadata{});
	drain();

	// heal the partition
	context.set_link(0, 1, true);
	context.set_link(1, 2, true);
	drain();
	REQUIRE(context.servers_converged());

	// phase 7: a short mixed burst with everything in flight, then settle
	std::mt19937 rng(999);
	auto pick = [&](int n) { return static_cast<int>(rng() % n); };
	for(int r = 0; r != 40; ++r) {
		switch(pick(5)) {
		case 0:
		case 1: context.client(pick(6)).engine.sync_object_change(create_object_id(), metadata{}); break;
		case 2: rotate_key(pick(6), all_members); break;
		case 3: {
			auto& l = context.links[pick(static_cast<int>(context.links.size()))];
			context.set_link(l.a, l.b, !l.up);
			break;
		}
		case 4: context.handle_events(); break;
		}
	}
	for(auto const& l : context.links) {
		context.set_link(l.a, l.b, true);
	}
	drain();

	CHECK(context.servers_converged());
	CHECK(context.server_n(0).sync.current_sequence_number()
		== context.server_n(1).sync.current_sequence_number());
	CHECK(context.server_n(1).sync.current_sequence_number()
		== context.server_n(2).sync.current_sequence_number());
	context.print_summary();
}

// (26) the M3 stress: random commits, membership changes, partitions and clients
// hopping between replicas mid-flight (the 4.5 resync); after the dust settles every
// replica has converged (plan 4.7). Bounded here; longer runs by bumping rounds
TEST_CASE("multi server stress", "[stress]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	setup_three(context, 2);   // six clients, two on each server
	context.add_link(0, 2, 1);

	std::mt19937 rng(12345);
	auto pick = [&](int n) { return static_cast<int>(rng() % n); };
	int const client_count = 6;

	int const rounds = 120;
	for(int round = 0; round != rounds; ++round) {
		switch(pick(7)) {
		case 0:
		case 1:
		case 2: // a data change from a random client
			context.client(pick(client_count)).engine.sync_object_change(create_object_id(), metadata{});
			break;
		case 3: { // a membership change from a random client (concurrent D9 merges)
			auto& c = context.client(pick(client_count));
			users delta{users_change_mode::delta};
			auto const& target = context.client(2).user;
			if(pick(2) == 0) {
				delta.add(util::user_access{target, util::access_type::data_write_access});
			} else {
				delta.remove(target);
			}
			c.engine.sync_user_change(encrypt_last_key_for_users(delta, c.cc));
			break;
		}
		case 4: { // toggle a random link
			auto& l = context.links[pick(static_cast<int>(context.links.size()))];
			context.set_link(l.a, l.b, !l.up);
			break;
		}
		case 5: { // a client hops to a random replica (the 4.5 resync mid-flight)
			auto const c = pick(client_count);
			context.disconnect_client(c);
			context.handle_events();
			context.connect_client_to(c, pick(3));
			break;
		}
		case 6: // let things move a little (never to quiet: commits land mid-flight)
			context.handle_events();
			context.handle_events();
			break;
		}
	}

	// the dust settles: all links up, everything drains
	for(auto const& l : context.links) {
		context.set_link(l.a, l.b, true);
	}
	while(context.handle_events()) {}

	CHECK(context.servers_converged());
	CHECK(context.server_n(0).sync.current_sequence_number()
		== context.server_n(1).sync.current_sequence_number());
	CHECK(context.server_n(1).sync.current_sequence_number()
		== context.server_n(2).sync.current_sequence_number());
	context.print_summary();
}

}
