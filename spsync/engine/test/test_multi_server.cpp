#include <spsync/test/test_sync_server.hpp>
#include <spsync/client/record_util.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <cstdlib>
#include <random>

namespace securepath::sync {
using namespace securepath::sync::util;

namespace {

/// integer from the environment, the default when unset or malformed (long stress runs
/// set SPSYNC_STRESS_ROUNDS / SPSYNC_STRESS_SEED without a rebuild)
int env_int(char const* name, int def) {
	int ret = def;
	if(auto const v = std::getenv(name)) {
		try {
			ret = std::stoi(v);
		} catch(std::exception const&) {
			ret = def;
		}
	}
	return ret;
}

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

/// the six clients of the full scenario and the stress, two on each server
int constexpr client_count = 6;

/// a random pick of [0, n) from a seeded generator
struct dice {
	explicit dice(int seed)
	: rng(static_cast<std::mt19937::result_type>(seed))
	{
	}

	int operator()(int n) {
		return static_cast<int>(rng() % n);
	}

public:
	std::mt19937 rng;
};

/// a random link goes down, or comes back up
void toggle_random_link(test::test_sync_context& context, dice& pick) {
	auto& l = context.links[pick(static_cast<int>(context.links.size()))];
	context.set_link(l.a, l.b, !l.up);
}

/// the dust settles: all links up, everything drains
void settle(test::test_sync_context& context) {
	for(auto const& l : context.links) {
		context.set_link(l.a, l.b, true);
	}
	while(context.handle_events()) {}
}

/// every replica converged, all at the same head
void check_converged_heads(test::test_sync_context& context) {
	CHECK(context.servers_converged());
	CHECK(context.server_n(0).sync.current_sequence_number()
		== context.server_n(1).sync.current_sequence_number());
	CHECK(context.server_n(1).sync.current_sequence_number()
		== context.server_n(2).sync.current_sequence_number());
}

/// the three replicas and six clients of the full scenario, with the moves its phases make
struct full_scenario {
	full_scenario() {
		setup_three(context, 2);   // clients 0,3 on server 0; 1,4 on server 1; 2,5 on server 2
	}

	void drain() {
		while(context.handle_events()) {}
	}

	/// everything drained, every replica at the same records
	void require_converged() {
		drain();
		REQUIRE(context.servers_converged());
	}

	/// a data change from `client`
	void change(int client) {
		context.client(client).engine.sync_object_change(create_object_id(), metadata{});
	}

	/// a membership change from `client` removing `member` (add is a no-op re-affirm here)
	void remove_member(int client, int member) {
		auto& c = context.client(client);
		users delta{users_change_mode::delta};
		delta.remove(context.client(member).user);
		c.engine.sync_user_change(encrypt_last_key_for_users(delta, c.cc));
	}

	/// rotate the encryption key from `client`, distributing the fresh key to `members`
	void rotate_key(int client, std::vector<int> const& members) {
		auto& c = context.client(client);
		c.enc_keys.create_key();   // a fresh key becomes this client's current
		users delta{users_change_mode::delta};
		for(int m : members) {
			delta.add(util::user_access{context.client(m).user, util::access_type::data_write_access});
		}
		c.engine.sync_user_change(encrypt_last_key_for_users(delta, c.cc));
	}

	/// seal a segment from `client` (needs its local commits flushed first, SEG 2)
	void seal_segment(int client) {
		drain();
		try {
			context.client(client).engine.sync_segment_end(metadata{});
		} catch(std::exception const& e) {
			LOG_INFO("segment not sealed: {}", e.what());
		}
		drain();
	}

	/// partition, commits on both sides (incl. a rotation), a client hop, heal
	void partition_hop_heal() {
		context.set_link(0, 1, false);
		context.set_link(1, 2, false);   // isolate server 1
		rotate_key(0, all_members);
		change(0);
		change(1);
		drain();
		CHECK(!context.servers_converged());

		// client 1 hops off the isolated server 1 onto server 2 and keeps working
		context.disconnect_client(1);
		drain();
		context.connect_client_to(1, 2);
		drain();
		change(1);
		drain();

		// heal the partition
		context.set_link(0, 1, true);
		context.set_link(1, 2, true);
	}

	/// a short mixed burst with everything in flight, then settle
	void mixed_burst() {
		dice pick{999};
		for(int r = 0; r != 40; ++r) {
			switch(pick(5)) {
			case 0:
			case 1: change(pick(6)); break;
			case 2: rotate_key(pick(6), all_members); break;
			case 3: toggle_random_link(context, pick); break;
			case 4: context.handle_events(); break;
			}
		}
		settle(context);
	}

public:
	test::test_sync_context context{chain_sync_config{sync_mode::allow_all}};
	std::vector<int> const all_members{0, 1, 2, 3, 4, 5};
};

/// a membership change from a random client (concurrent D9 merges)
void random_membership_change(test::test_sync_context& context, dice& pick) {
	auto& c = context.client(pick(client_count));
	users delta{users_change_mode::delta};
	auto const& target = context.client(2).user;
	if(pick(2) == 0) {
		delta.add(util::user_access{target, util::access_type::data_write_access});
	} else {
		delta.remove(target);
	}
	c.engine.sync_user_change(encrypt_last_key_for_users(delta, c.cc));
}

/// one move of the stress: a random client or the network does something
void stress_move(test::test_sync_context& context, dice& pick) {
	switch(pick(7)) {
	case 0:
	case 1:
	case 2: // a data change from a random client
		context.client(pick(client_count)).engine.sync_object_change(create_object_id(), metadata{});
		break;
	case 3:
		random_membership_change(context, pick);
		break;
	case 4: // toggle a random link
		toggle_random_link(context, pick);
		break;
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
	full_scenario s;

	// phase 1: plain data changes from every client spread across the replicas
	for(int i : s.all_members) {
		s.change(i);
	}
	s.require_converged();

	// phase 2: a membership change (add is a no-op re-affirm here; remove client 5)
	s.remove_member(0, 5);
	s.require_converged();

	// phase 3: a key rotation, then data committed under the new key stays readable
	s.rotate_key(1, s.all_members);
	s.drain();
	for(int i : {0, 2, 4}) {
		s.change(i);
	}
	s.require_converged();

	// phase 4: concurrent rotations on two clients -> two keys at one sequence (D9);
	// records committed under each remain readable everywhere
	s.rotate_key(0, s.all_members);
	s.rotate_key(2, s.all_members);
	s.change(0);
	s.change(2);
	s.require_converged();

	// phase 5: a segment seal, then more data on top of the sealed history
	s.seal_segment(3);
	REQUIRE(s.context.servers_converged());
	s.change(4);
	s.require_converged();

	// phase 6: partition, commits on both sides (incl. a rotation), a client hop, heal
	s.partition_hop_heal();
	s.require_converged();

	// phase 7: a short mixed burst with everything in flight, then settle
	s.mixed_burst();
	check_converged_heads(s.context);
	s.context.print_summary();
}

// (27) a hop interrupts the 4.5 resync refetch and the client comes back to the same
// replica while a live push already delivered a newer record: the received sequences
// have a gap (weak modes store gapped records) which must be refetched - the client is
// not up to date just because it holds the highest sequence. A demoted record inside the
// gap is confirmed by its copy instead of being recommitted forever (the M3 stress found
// that loop: the drain never finished)
TEST_CASE("multi server interrupted refetch", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	setup_three(context);

	// enough records that a refetch takes several 30 record responses
	for(int i = 0; i != 40; ++i) {
		for(int c = 0; c != 3; ++c) {
			context.client(c).engine.sync_object_change(create_object_id(), metadata{});
		}
	}
	while(context.handle_events()) {}
	REQUIRE(context.servers_converged());
	auto const before = context.server_n(1).sync.current_sequence_number();
	REQUIRE(before > sequence_number{100});

	// client 0 hops to server 1: the resync demotes everything and refetches from the start
	context.disconnect_client(0);
	context.handle_events();
	context.connect_client_to(0, 1);
	context.handle_events();   // the sequence answer: resync, first batch requested
	context.handle_events();   // first batch in, next requested
	// a record committed on the replica meanwhile reaches client 0 as a live push, so
	// the client holds the newest sequence while the refetch is still in the middle
	context.client(1).engine.sync_object_change(create_object_id(), metadata{});
	context.handle_events();
	context.handle_events();
	auto& records = context.client(0).io.records();
	REQUIRE(records.highest_sequence_number() > before);
	REQUIRE(records.first_missing_sequence().is_valid());

	// the connection drops mid refetch (the outstanding response is lost with it) and
	// comes back to the same replica
	context.disconnect_client(0);
	context.handle_events();
	context.connect_client_to(0, 1);
	while(context.handle_events()) {}

	CHECK(!records.first_missing_sequence().is_valid());
	CHECK(!records.find_first_pending_commit());
	CHECK(records.highest_sequence_number() == context.server_n(1).sync.current_sequence_number());
	CHECK(context.servers_converged());
}

// (26) the M3 stress: random commits, membership changes, partitions and clients
// hopping between replicas mid-flight (the 4.5 resync); after the dust settles every
// replica has converged (plan 4.7). Bounded by default; the M3 hours-long shakedown runs
// it in a loop with SPSYNC_STRESS_ROUNDS and SPSYNC_STRESS_SEED in the environment
TEST_CASE("multi server stress", "[stress]") {
	int const rounds = env_int("SPSYNC_STRESS_ROUNDS", 120);
	int const seed = env_int("SPSYNC_STRESS_SEED", 12345);
	std::cout << std::format("stress: {} rounds, seed {}\n", rounds, seed);

	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	setup_three(context, 2);   // six clients, two on each server
	context.add_link(0, 2, 1);

	dice pick{seed};
	for(int round = 0; round != rounds; ++round) {
		stress_move(context, pick);
	}

	settle(context);
	check_converged_heads(context);
	context.print_summary();
}

}
