#include <spsync/test/test_context.hpp>

#include <spsync/server/server_lib/storage_server.hpp>
#include <spsync/server/server_lib/storage.hpp>

#include <spsync/protocol/error.hpp>

#include <spsync/test/test_block_creator.hpp>
#include <spsync/test/test_ports.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>
#include <utility>

namespace securepath::sync {
namespace {

/// the peer entry of the server in the slot of this file (test_ports.hpp)
peer_config s2s_peer(int slot, crypto::public_key_id key) {
	return test::peer_of(test::s2s_test_slots + slot, std::move(key));
}

/// a server in the slot of this file, its s2s listener on loopback
storage_server_params s2s_test_params(std::string root, int slot, std::vector<peer_config> peers) {
	auto const ports = test::server_ports(test::s2s_test_slots + slot);
	storage_server_params p;
	p.storage_root = std::move(root);
	p.storage_server_port = ports.client;
	p.s2s_endpoint = asio::ip::tcp::endpoint(asio::ip::address_v4::loopback(), ports.s2s);
	p.peers = std::move(peers);
	return p;
}

/// the modes of a replicated storage of these tests
storage_modes weak_modes() {
	return storage_modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::weak};
}

/// the modes of a storage no peer replicates
storage_modes local_modes() {
	return storage_modes{sync_mode::allow_all, auth_mode::sign_records};
}

/// both servers see the other as a connected peer
bool peers_connected(storage_server const& a, storage_server const& b) {
	return !a.connected_peers().empty() && !b.connected_peers().empty();
}

/// the storage opened on both servers with the modes
std::pair<std::shared_ptr<storage>, std::shared_ptr<storage>> open_on_both(storage_server& a, storage_server& b
	, protocol::storage_id const& sid, storage_modes const& modes) {
	auto sa = a.open_storage(sid, modes);
	auto sb = b.open_storage(sid, modes);
	REQUIRE(sa);
	REQUIRE(sb);
	return {std::move(sa), std::move(sb)};
}

/// the sorted record tags of [1, last]; equal sets mean converged (sequences may differ, D4)
std::vector<octet_vector> tag_set(storage& s, sequence_number last) {
	std::vector<octet_vector> tags;
	for(auto const& r : s.get_records(sequence_number{1}, last)) {
		tags.push_back(r.tag());
	}
	std::ranges::sort(tags);
	return tags;
}

/**
 * Two peered servers in slots of this file: contexts 0 and 1 with pk handshakes (the
 * servers accept and dial over the same context: role dispatched handshake) and shared
 * keys unless said otherwise; the roots are removed before and after.
 */
struct peer_pair {
	peer_pair(std::string root_a, std::string root_b, int slot_a, int slot_b, bool share_keys = true)
	: roots{std::move(root_a), std::move(root_b)}
	, slots{slot_a, slot_b}
	{
		clean();
		tctx.add_client(2);
		if(share_keys) {
			tctx.share_client_keys();
		}
		network::enable_pk_handshake(tctx.client_context(0));
		network::enable_pk_handshake(tctx.client_context(1));
	}

	~peer_pair() {
		clean();
	}

	crypto::public_key_id key(std::size_t i) const {
		return tctx.key_id(i);
	}

	network::context& context(std::size_t i) {
		return tctx.client_context(i);
	}

	crypto::private_key signer(std::size_t i) {
		return *context(i).private_data().my_private_key();
	}

	/// the parameters of server i, peered with the other one
	storage_server_params params(std::size_t i, std::optional<std::chrono::seconds> anti_entropy = {}) const {
		auto p = s2s_test_params(roots[i], slots[i], {s2s_peer(slots[1 - i], key(1 - i))});
		if(anti_entropy) {
			p.anti_entropy_interval = *anti_entropy;
		}
		return p;
	}

	/// a block creator signing with the key of context i
	test::test_block_creator creator(std::size_t i) {
		test::test_block_creator ret;
		ret.signer = signer(i);
		return ret;
	}

	void clean() {
		for(auto const& root : roots) {
			std::filesystem::remove_all(root);
		}
	}

public:
	test::test_context tctx;
	std::array<std::string, 2> roots;
	std::array<int, 2> slots;
};

/// the head of the origin among the announced ones
origin_head own_head(std::vector<origin_head> const& heads, crypto::public_key_id const& origin) {
	auto it = std::ranges::find(heads, origin, &origin_head::origin);
	REQUIRE(it != heads.end());
	return *it;
}

/// the origin's signed assignment is what the replica's log keeps, and its origin head advanced
void check_pushed_assignment(storage& sb, protocol::storage_id const& sid, crypto::public_key_id const& origin
	, network::context& replica_context) {
	auto envs_b = sb.get_envelopes(sequence_number{1}, sequence_number{1});
	REQUIRE(envs_b.size() == 1);
	CHECK(envs_b[0].origin() == origin);
	CHECK(envs_b[0].is_signed());
	CHECK(!envs_b[0].verify(sid, replica_context.public_keys()));
	CHECK(envs_b[0].block().sequence() == sequence_number{1});
	auto head = sb.origin_heads().find(origin);
	REQUIRE(head);
	CHECK(head->block.sequence == sequence_number{1});
}

/// a copy of the client commits a data change: refused as out of sync
void check_stale_rejected(storage& s, test::test_block_creator const& client) {
	auto stale = client;
	CHECK(check_result_error(s.commit_block(stale.test_data_change()).block, protocol::errc::record_out_of_sync));
}

/// the roots of the bootstrap test's servers A, B and C
std::array<std::string, 3> const bootstrap_roots{"test-s2s-ba", "test-s2s-bb", "test-s2s-bc"};

/// contexts 0-2 = A, B, C (the newcomer), 3 = a client that registered at A and B
crypto::private_key bootstrap_contexts(test::test_context& tctx) {
	tctx.add_client(4);
	for(std::size_t i = 0; i != 3; ++i) {
		network::enable_pk_handshake(tctx.client_context(i));
	}
	auto const client_key = *tctx.client_context(3).private_data().my_private_key();
	tctx.client_context(0).public_keys().insert(client_key.public_key());
	tctx.client_context(1).public_keys().insert(client_key.public_key());
	return client_key;
}

/// the parameters of server i of the three, peered with the other two, anti-entropy every second
storage_server_params bootstrap_params(test::test_context const& tctx, std::size_t i) {
	std::vector<peer_config> peers;
	for(std::size_t other = 0; other != 3; ++other) {
		if(other != i) {
			peers.push_back(s2s_peer(12 + static_cast<int>(other), tctx.key_id(other)));
		}
	}
	auto p = s2s_test_params(bootstrap_roots[i], 12 + static_cast<int>(i), std::move(peers));
	p.anti_entropy_interval = std::chrono::seconds{1};
	return p;
}

/// records of both origins in both storages, all signed by the client
void fill_bootstrap_storages(storage& sa1, storage& sb1, storage& sa2, storage& sb2, crypto::private_key const& client_key) {
	test::test_block_creator creator1;
	creator1.signer = client_key;
	REQUIRE(sa1.commit_block(creator1.test_user_change()).block);
	REQUIRE(sa1.commit_block(creator1.test_data_change()).block);
	WAIT_CHECK(sb1.current_sequence_number() == sequence_number{2}, 5s);
	test::test_block_creator creator1b = creator1;
	REQUIRE(sb1.commit_block(creator1b.test_data_change()).block);
	WAIT_CHECK(sa1.current_sequence_number() == sequence_number{3}, 5s);
	test::test_block_creator creator2;
	creator2.signer = client_key;
	REQUIRE(sb2.commit_block(creator2.test_user_change()).block);
	WAIT_CHECK(sa2.current_sequence_number() == sequence_number{1}, 5s);
}

}

// two in-process storage servers on loopback authenticate each other and exchange the
// heads of their replicated storages (plan 4.1)
TEST_CASE("s2s peers exchange heads", "[unit]") {
	peer_pair pair{"test-s2s-a", "test-s2s-b", 0, 1};
	auto const key_a = pair.key(0);
	auto const key_b = pair.key(1);
	storage_server a(pair.context(0), pair.params(0));
	storage_server b(pair.context(1), pair.params(1));

	// the same storage exists on both with replicated modes, each with one own record
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	auto [sa, sb] = open_on_both(a, b, sid, weak_modes());
	auto creator_a = pair.creator(0);
	REQUIRE(sa->commit_block(creator_a.test_user_change()).block);
	auto creator_b = pair.creator(1);
	REQUIRE(sb->commit_block(creator_b.test_user_change()).block);

	a.start();
	b.start();
	CHECK(a.identity().server_id == key_a);
	CHECK(a.s2s_local_endpoint().has_value());

	// both directions get connected, authenticated and announce their heads
	WAIT_CHECK(!b.heads_of_peer(key_a, sid).empty(), 5s);
	WAIT_CHECK(!a.heads_of_peer(key_b, sid).empty(), 5s);

	// the peers dial each other, so the announcement seen can be the one of the second
	// connection which may already carry the origin pulled over the first: look at the
	// announcer's own origin. An own head is the announcer's local chain head: 1 record,
	// or 2 once the first connection already pulled the other's record
	auto head_a = own_head(b.heads_of_peer(key_a, sid), key_a);
	CHECK(head_a.term == 0);
	CHECK(head_a.block.sequence >= sequence_number{1});
	CHECK(head_a.block.sequence <= sequence_number{2});
	if(head_a.block.sequence == sequence_number{1}) {
		CHECK(head_a.block.hash == creator_a.last_chain_hash);
	}
	auto head_b = own_head(a.heads_of_peer(key_b, sid), key_b);
	CHECK(head_b.block.sequence >= sequence_number{1});

	a.close();
	b.close();
}

// weak-mode push on commit (plan 4.2): a commit on one server appears on the other under
// its own sequence, the origin's signed assignment is kept and concurrent commits
// converge to the same tag set
TEST_CASE("s2s weak push on commit", "[unit]") {
	peer_pair pair{"test-s2s-pa", "test-s2s-pb", 2, 3};
	storage_server a(pair.context(0), pair.params(0));
	storage_server b(pair.context(1), pair.params(1));
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	auto [sa, sb] = open_on_both(a, b, sid, weak_modes());
	a.start();
	b.start();
	WAIT_CHECK(peers_connected(a, b), 5s);

	// commit on A appears on B
	auto creator_a = pair.creator(0);
	auto outcome = sa->commit_block(creator_a.test_user_change());
	REQUIRE(outcome.block);
	REQUIRE(outcome.envelope);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);
	auto recs_b = sb->get_records(sequence_number{1}, sequence_number{1});
	REQUIRE(recs_b.size() == 1);
	CHECK(recs_b[0].tag() == creator_a.last_tag);
	check_pushed_assignment(*sb, sid, pair.key(0), pair.context(1));

	// a duplicate is ignored without growing the chain
	CHECK(!sb->apply_foreign(*outcome.envelope));
	CHECK(sb->current_sequence_number() == sequence_number{1});

	// concurrent commit on B: both converge to the same tag set (sequences are local, D4)
	auto creator_b = pair.creator(1);
	REQUIRE(sb->commit_block(creator_b.test_user_change()).block);
	WAIT_CHECK(sa->current_sequence_number() == sequence_number{2}, 5s);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{2}, 5s);
	CHECK(tag_set(*sa, sequence_number{2}) == tag_set(*sb, sequence_number{2}));

	a.close();
	b.close();
}

// tag-bound seen rule across replicas (plan 4.3/D4): a stale client is rejected and a
// fresh one accepted on either replica, with replica-local sequences free to differ
TEST_CASE("s2s tag bound rules across replicas", "[unit]") {
	peer_pair pair{"test-s2s-ta", "test-s2s-tb", 4, 5};
	storage_server a(pair.context(0), pair.params(0));
	storage_server b(pair.context(1), pair.params(1));
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	storage_modes const modes{sync_mode::require_special_seen, auth_mode::sign_records, replication_mode::weak};
	auto [sa, sb] = open_on_both(a, b, sid, modes);
	a.start();
	b.start();
	WAIT_CHECK(peers_connected(a, b), 5s);

	// the first special record spreads to both replicas
	auto client_a = pair.creator(0);
	REQUIRE(sa->commit_block(client_a.test_user_change()).block);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);

	auto stale = client_a;      // saw only the first special record
	auto client_b = client_a;   // a client of B with the same view
	client_b.signer = pair.signer(1);
	auto fresh = client_a;

	// a data change lands on B, then a membership change on A; the change ends up at
	// different local sequences on the two replicas
	REQUIRE(sb->commit_block(client_b.test_data_change()).block);
	REQUIRE(sa->commit_block(fresh.test_user_change()).block);
	WAIT_CHECK(sa->current_sequence_number() == sequence_number{3}, 5s);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{3}, 5s);

	// the stale client is rejected on either replica
	check_stale_rejected(*sa, stale);
	check_stale_rejected(*sb, stale);

	// the client that saw the membership change is accepted on the OTHER replica even
	// though the change sits at a different local sequence there
	REQUIRE(sb->commit_block(fresh.test_data_change()).block);
	WAIT_CHECK(sa->current_sequence_number() == sequence_number{4}, 5s);
	CHECK(tag_set(*sa, sequence_number{4}) == tag_set(*sb, sequence_number{4}));

	a.close();
	b.close();
}

// anti-entropy (plan 4.4): commits made while a peer is down (or partitioned away) are
// pulled on reconnect via the heads exchange, both directions, idempotently
TEST_CASE("s2s anti-entropy heals partitions", "[unit]") {
	peer_pair pair{"test-s2s-ea", "test-s2s-eb", 6, 7};
	auto const params_b = pair.params(1, std::chrono::seconds{1});
	storage_server a(pair.context(0), pair.params(0, std::chrono::seconds{1}));
	auto b = std::make_unique<storage_server>(pair.context(1), params_b);
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	auto [sa, sb] = open_on_both(a, *b, sid, weak_modes());
	a.start();
	b->start();
	WAIT_CHECK(peers_connected(a, *b), 5s);

	// a first record spreads while both are up
	auto client_a = pair.creator(0);
	REQUIRE(sa->commit_block(client_a.test_user_change()).block);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);

	// partition: B's server goes down; its storage keeps taking local commits
	b->close();
	auto client_b = client_a;
	client_b.signer = pair.signer(1);
	REQUIRE(sa->commit_block(client_a.test_data_change()).block);
	REQUIRE(sb->commit_block(client_b.test_data_change()).block);
	CHECK(sa->current_sequence_number() == sequence_number{2});
	CHECK(sb->current_sequence_number() == sequence_number{2});

	// heal: B restarts on the same root; both directions catch up via the heads exchange
	sb.reset();
	b.reset();
	storage_server b2(pair.context(1), params_b);
	auto sb2 = b2.open_storage(sid);
	REQUIRE(sb2);
	b2.start();
	WAIT_CHECK((sa->current_sequence_number() == sequence_number{3}
		&& sb2->current_sequence_number() == sequence_number{3}), 15s);
	CHECK(tag_set(*sa, sequence_number{3}) == tag_set(*sb2, sequence_number{3}));

	// the periodic announcements keep running without duplicating anything
	std::this_thread::sleep_for(std::chrono::seconds{2});
	CHECK(sa->current_sequence_number() == sequence_number{3});
	CHECK(sb2->current_sequence_number() == sequence_number{3});

	a.close();
	b2.close();
}

// a storage created on one replica appears on the others (the heads and pushes carry its
// modes, plan 4.2/4.4): B never opened it and gets both the storage and the record
TEST_CASE("s2s replica creates the storage on first contact", "[unit]") {
	// no pre-shared keys: B learns A's key from the authenticated peer handshake and
	// verifies A's signed assignments (and A's signed record) with it
	peer_pair pair{"test-s2s-ca", "test-s2s-cb", 8, 9, false};
	storage_server a(pair.context(0), pair.params(0));
	storage_server b(pair.context(1), pair.params(1));

	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	auto sa = a.open_storage(sid, weak_modes());
	REQUIRE(sa);
	a.start();
	b.start();
	WAIT_CHECK(peers_connected(a, b), 5s);

	// an unreplicated storage is never created by a peer's announcement
	protocol::storage_id const local_sid = securepath::test::random_octet_vector(8);
	REQUIRE(a.open_storage(local_sid, local_modes()));

	auto creator_a = pair.creator(0);
	REQUIRE(sa->commit_block(creator_a.test_user_change()).block);

	WAIT_CHECK(b.has_storage(sid), 5s);
	auto sb = b.open_storage(sid, weak_modes());
	REQUIRE(sb);
	CHECK(sb->modes() == sa->modes());   // incl. the limits A filled from its defaults
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);
	CHECK(!b.has_storage(local_sid));

	a.close();
	b.close();
}

// a restarted server reopens its replicated storages from disk (plan 5.1): nobody has to
// connect to it before it announces heads, takes pushes and serves pulls again
TEST_CASE("s2s restart reopens replicated storages", "[unit]") {
	peer_pair pair{"test-s2s-ra", "test-s2s-rb", 10, 11};
	auto const params_a = pair.params(0);
	auto const params_b = pair.params(1);
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	protocol::storage_id const local_sid = securepath::test::random_octet_vector(8);
	auto creator_a = pair.creator(0);
	{
		// A holds the storage with one record (and an unreplicated one) and goes down
		storage_server a(pair.context(0), params_a);
		auto sa = a.open_storage(sid, weak_modes());
		REQUIRE(sa);
		REQUIRE(sa->commit_block(creator_a.test_user_change()).block);
		REQUIRE(a.open_storage(local_sid, local_modes()));
		a.close();
	}

	storage_server b(pair.context(1), params_b);
	b.start();
	storage_server a(pair.context(0), params_a);
	a.start();
	WAIT_CHECK(peers_connected(a, b), 5s);

	// only the replicated storage was reopened at start
	CHECK(a.is_open(sid));
	CHECK(!a.is_open(local_sid));

	// A announced the storage it reopened: B created its replica and pulled the record
	WAIT_CHECK(b.has_storage(sid), 5s);
	auto sb = b.open_storage(sid, weak_modes());
	REQUIRE(sb);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);

	// and a push from B lands in A's reopened storage without any client opening it
	auto creator_b = creator_a;
	creator_b.signer = pair.signer(1);
	REQUIRE(sb->commit_block(creator_b.test_data_change()).block);
	auto sa = a.open_storage(sid, weak_modes());
	REQUIRE(sa);
	WAIT_CHECK(sa->current_sequence_number() == sequence_number{2}, 5s);

	a.close();
	b.close();
}

// (plan 5.2) a new replica joins a running cluster: it learns every replicated storage
// from the heads its peers announce, pulls every origin from the start, verifies the
// origins' assignments and the clients' signatures - fetching the key of a signer it
// never saw from the peer that holds the record - and reports syncing until caught up
TEST_CASE("s2s bootstrap a new replica", "[unit]") {
	for(auto const& d : bootstrap_roots) {
		std::filesystem::remove_all(d);
	}
	test::test_context tctx;
	auto const client_key = bootstrap_contexts(tctx);

	storage_server a(tctx.client_context(0), bootstrap_params(tctx, 0));
	storage_server b(tctx.client_context(1), bootstrap_params(tctx, 1));
	protocol::storage_id const sid1 = securepath::test::random_octet_vector(8);
	protocol::storage_id const sid2 = securepath::test::random_octet_vector(8);
	protocol::storage_id const local_sid = securepath::test::random_octet_vector(8);
	auto [sa1, sb1] = open_on_both(a, b, sid1, weak_modes());
	auto [sa2, sb2] = open_on_both(a, b, sid2, weak_modes());
	REQUIRE(a.open_storage(local_sid, local_modes()));
	a.start();
	b.start();
	WAIT_CHECK(peers_connected(a, b), 5s);
	fill_bootstrap_storages(*sa1, *sb1, *sa2, *sb2, client_key);

	// C joins: nothing configured on it but the peers
	storage_server c(tctx.client_context(2), bootstrap_params(tctx, 2));
	c.start();
	WAIT_CHECK((c.has_storage(sid1) && c.has_storage(sid2)), 10s);
	auto sc1 = c.open_storage(sid1, weak_modes());
	auto sc2 = c.open_storage(sid2, weak_modes());
	REQUIRE(sc1);
	REQUIRE(sc2);
	WAIT_CHECK(tag_set(*sc1, sequence_number{3}) == tag_set(*sa1, sequence_number{3}), 10s);
	WAIT_CHECK(tag_set(*sc2, sequence_number{1}) == tag_set(*sa2, sequence_number{1}), 10s);
	WAIT_CHECK((!c.is_syncing(sid1) && !c.is_syncing(sid2)), 10s);
	CHECK(!sc1->bootstrapping());
	CHECK(!c.has_storage(local_sid));
	// the signer's key came from a peer
	CHECK(tctx.client_context(2).public_keys().find(client_key.id()));

	a.close();
	b.close();
	c.close();
	for(auto const& d : bootstrap_roots) {
		std::filesystem::remove_all(d);
	}
}

// an own-origin pull is served by the origin's assignments: with more than a batch of
// foreign records committed in between, serving the local range never made progress on
// the origin's sequences and the pull stalled for good
TEST_CASE("s2s own origin pull across many foreign records", "[unit]") {
	peer_pair pair{"test-s2s-oa", "test-s2s-ob", 15, 16};
	auto const params_b = pair.params(1, std::chrono::seconds{1});
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	storage_server a(pair.context(0), pair.params(0, std::chrono::seconds{1}));
	auto b = std::make_unique<storage_server>(pair.context(1), params_b);
	auto [sa, sb] = open_on_both(a, *b, sid, weak_modes());
	a.start();
	b->start();
	WAIT_CHECK(peers_connected(a, *b), 5s);

	// A's first own record, then B commits more than a batch of records that A applies
	auto creator_a = pair.creator(0);
	REQUIRE(sa->commit_block(creator_a.test_user_change()).block);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);
	auto creator_b = creator_a;
	creator_b.signer = pair.signer(1);
	for(int i = 0; i != 40; ++i) {
		REQUIRE(sb->commit_block(creator_b.test_data_change()).block);
	}
	WAIT_CHECK(sa->current_sequence_number() == sequence_number{41}, 10s);

	// B goes down, A commits its second own record (local sequence 42), B comes back
	// and must pull it although 40 foreign records sit between A's two records
	b->close();
	sb.reset();
	b.reset();
	REQUIRE(sa->commit_block(creator_a.test_data_change()).block);
	auto const second_tag = creator_a.last_tag;
	b = std::make_unique<storage_server>(pair.context(1), params_b);
	sb = b->open_storage(sid, weak_modes());
	REQUIRE(sb);
	b->start();
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{42}, 10s);
	auto const last = sb->get_records(sequence_number{42}, sequence_number{42});
	REQUIRE(last.size() == 1);
	CHECK(last.front().tag() == second_tag);

	a.close();
	b->close();
}

// (plan 5.3) a replica holding a record the origin assigned a sequence to differently -
// the origin's history parts from the replica's there - refuses the origin's record at
// that sequence, pulls nothing of that history and is not "syncing" for it
TEST_CASE("s2s divergent origin history is not pulled", "[unit]") {
	peer_pair pair{"test-s2s-da", "test-s2s-db", 21, 22};
	auto const key_a = pair.key(0);
	storage_server a(pair.context(0), pair.params(0, std::chrono::seconds{1}));
	storage_server b(pair.context(1), pair.params(1, std::chrono::seconds{1}));
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	auto [sa, sb] = open_on_both(a, b, sid, weak_modes());
	a.start();
	b.start();
	WAIT_CHECK(peers_connected(a, b), 5s);

	auto creator = pair.creator(0);
	REQUIRE(sa->commit_block(creator.test_user_change()).block);
	REQUIRE(sa->commit_block(creator.test_data_change()).block);
	REQUIRE(sa->commit_block(creator.test_data_change()).block);
	WAIT_REQUIRE(sb->current_sequence_number() == sequence_number{3}, 5s);

	// B takes a record A's key assigned sequence 4 to, before A's own fourth record
	auto other = creator;
	auto forged = other.test_data_change();
	forged.set_sequence_and_parent_hash(sequence_number{4}, sa->get_records(sequence_number{3}, sequence_number{3}).at(0).hash());
	block_envelope env{forged, key_a};
	env.sign(sid, pair.signer(0));
	REQUIRE(!sb->apply_foreign(env));
	CHECK(sb->known_origin_seq(key_a) == sequence_number{4});

	// A's real fourth record is pushed and refused: the sequence is held under another hash
	auto const fourth = creator.test_data_change();
	REQUIRE(sa->commit_block(fourth).block);
	auto const announced_head = [&] {
		auto const heads = b.heads_of_peer(key_a, sid);
		auto it = std::ranges::find(heads, key_a, &origin_head::origin);
		return it == heads.end() ? sequence_number{} : it->block.sequence;
	};
	// the next announcement carries head 4 with samples: B sees the fork, pulls nothing
	// of it and does not count itself behind on that origin
	WAIT_REQUIRE(announced_head() == sequence_number{4}, 5s);
	CHECK(!b.is_syncing(sid));
	CHECK(!a.is_syncing(sid));
	auto tags = tag_set(*sb, sequence_number{4});
	CHECK(std::ranges::find(tags, forged.tag()) != tags.end());
	CHECK(std::ranges::find(tags, fourth.tag()) == tags.end());

	// what A assigns after that has no counterpart on B and applies as usual
	auto const fifth = creator.test_data_change();
	REQUIRE(sa->commit_block(fifth).block);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{5}, 5s);
	tags = tag_set(*sb, sequence_number{5});
	CHECK(std::ranges::find(tags, fifth.tag()) != tags.end());
	CHECK(std::ranges::find(tags, fourth.tag()) == tags.end());
	CHECK(sb->known_origin_seq(key_a) == sequence_number{5});

	a.close();
	b.close();
}

// the timer and link handlers of a storage server hold it weakly: a server that is
// closed and destroyed while its anti-entropy timer fires continuously and its link to
// an unreachable peer keeps reconnecting must go away cleanly
TEST_CASE("s2s server lifetime under running timers", "[unit]") {
	std::filesystem::remove_all("test-s2s-la");
	test::test_context tctx;
	tctx.add_client(2);
	network::enable_pk_handshake(tctx.client_context(0));
	auto const key_b = tctx.key_id(1);
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);

	for(int i = 0; i != 20; ++i) {
		// nobody listens on the peer port: the link dials, fails and schedules reconnects
		auto params = s2s_test_params("test-s2s-la", 17, {s2s_peer(18, key_b)});
		params.anti_entropy_interval = std::chrono::seconds{0};
		auto server = std::make_unique<storage_server>(tctx.client_context(0), params);
		REQUIRE(server->open_storage(sid, weak_modes()));
		server->start();
		std::this_thread::sleep_for(std::chrono::milliseconds{i % 5});
		server->close();
		server.reset();
	}
	std::filesystem::remove_all("test-s2s-la");
}

// a record above a mebibyte between replicas: pushed when it is committed, pulled by a
// replica that was away (the peer connection's deserialiser capped a message at 1 MiB)
TEST_CASE("s2s records above a mebibyte", "[unit]") {
	peer_pair pair{"test-s2s-ma", "test-s2s-mb", 19, 20};
	storage_server a(pair.context(0), pair.params(0));
	auto b = std::make_unique<storage_server>(pair.context(1), pair.params(1));
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	auto modes = weak_modes();
	modes.limits = storage_limits{max_record_size_range.highest, 0};
	auto [sa, sb] = open_on_both(a, *b, sid, modes);
	a.start();
	b->start();
	WAIT_REQUIRE(peers_connected(a, *b), 5s);

	auto creator = pair.creator(0);
	REQUIRE(sa->commit_block(creator.test_user_change()).block);
	auto const big = creator.test_big_data_change(1536 * 1024);
	REQUIRE(big.record_bytes().size() > 1024 * 1024);
	REQUIRE(sa->commit_block(big).block);

	// pushed
	WAIT_REQUIRE(sb->current_sequence_number() == sequence_number{2}, 20s);
	CHECK(sb->get_records(sequence_number{2}, sequence_number{2}).at(0).tag() == big.tag());

	// B goes away, A commits more big ones, B comes back and pulls them
	sb.reset();
	b->close();
	b.reset();
	for(int i = 0; i != 3; ++i) {
		REQUIRE(sa->commit_block(creator.test_big_data_change(1200 * 1024)).block);
	}
	storage_server back(pair.context(1), pair.params(1));
	back.start();
	auto sback = back.open_storage(sid);
	REQUIRE(sback);
	WAIT_CHECK(sback->current_sequence_number() == sequence_number{5}, 30s);
	CHECK(tag_set(*sback, sequence_number{5}) == tag_set(*sa, sequence_number{5}));

	back.close();
	a.close();
}

}
