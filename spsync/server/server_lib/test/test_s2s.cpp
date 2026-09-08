#include <spsync/test/test_context.hpp>

#include <spsync/server/server_lib/storage_server.hpp>
#include <spsync/server/server_lib/storage.hpp>

#include <spsync/protocol/error.hpp>

#include <spsync/test/test_block_creator.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <algorithm>
#include <filesystem>

namespace securepath::sync {
namespace {

storage_server_params s2s_test_params(std::string root, std::uint16_t port, std::uint16_t s2s_port,
	std::vector<peer_config> peers) {
	storage_server_params p;
	p.storage_root = std::move(root);
	p.storage_server_port = port;
	p.s2s_endpoint = asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), s2s_port);
	p.peers = std::move(peers);
	return p;
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

}

// two in-process storage servers on loopback authenticate each other and exchange the
// heads of their replicated storages (plan 4.1)
TEST_CASE("s2s peers exchange heads", "[unit]") {
	std::filesystem::remove_all("test-s2s-a");
	std::filesystem::remove_all("test-s2s-b");

	test::test_context tctx;
	tctx.add_client(2);
	tctx.share_client_keys();
	// the servers accept and dial over the same context: role dispatched handshake
	network::enable_pk_handshake(tctx.client_context(0));
	network::enable_pk_handshake(tctx.client_context(1));

	auto const key_a = tctx.key_id(0);
	auto const key_b = tctx.key_id(1);

	storage_server a(tctx.client_context(0),
		s2s_test_params("test-s2s-a", 42750, 42760, {peer_config{"127.0.0.1", 42761, key_b}}));
	storage_server b(tctx.client_context(1),
		s2s_test_params("test-s2s-b", 42751, 42761, {peer_config{"127.0.0.1", 42760, key_a}}));

	// the same storage exists on both with replicated modes, each with one own record
	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	storage_modes const modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::weak};
	auto sa = a.open_storage(sid, modes);
	auto sb = b.open_storage(sid, modes);
	REQUIRE(sa);
	REQUIRE(sb);

	test::test_block_creator creator_a;
	creator_a.signer = *tctx.client_context(0).private_data().my_private_key();
	REQUIRE(sa->commit_block(creator_a.test_user_change()).block);

	test::test_block_creator creator_b;
	creator_b.signer = *tctx.client_context(1).private_data().my_private_key();
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
	// announcer's own origin
	auto own_head = [](std::vector<origin_head> const& heads, crypto::public_key_id const& origin) {
		auto it = std::ranges::find(heads, origin, &origin_head::origin);
		REQUIRE(it != heads.end());
		return *it;
	};
	// an own head is the announcer's local chain head: 1 record, or 2 once the first
	// connection already pulled the other's record
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
	std::filesystem::remove_all("test-s2s-a");
	std::filesystem::remove_all("test-s2s-b");
}

// weak-mode push on commit (plan 4.2): a commit on one server appears on the other under
// its own sequence, the origin's signed assignment is kept and concurrent commits
// converge to the same tag set
TEST_CASE("s2s weak push on commit", "[unit]") {
	std::filesystem::remove_all("test-s2s-pa");
	std::filesystem::remove_all("test-s2s-pb");

	test::test_context tctx;
	tctx.add_client(2);
	tctx.share_client_keys();
	network::enable_pk_handshake(tctx.client_context(0));
	network::enable_pk_handshake(tctx.client_context(1));

	auto const key_a = tctx.key_id(0);
	auto const key_b = tctx.key_id(1);

	storage_server a(tctx.client_context(0),
		s2s_test_params("test-s2s-pa", 42752, 42762, {peer_config{"127.0.0.1", 42763, key_b}}));
	storage_server b(tctx.client_context(1),
		s2s_test_params("test-s2s-pb", 42753, 42763, {peer_config{"127.0.0.1", 42762, key_a}}));

	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	storage_modes const modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::weak};
	auto sa = a.open_storage(sid, modes);
	auto sb = b.open_storage(sid, modes);
	REQUIRE(sa);
	REQUIRE(sb);

	a.start();
	b.start();
	WAIT_CHECK((!a.connected_peers().empty() && !b.connected_peers().empty()), 5s);

	// commit on A appears on B
	test::test_block_creator creator_a;
	creator_a.signer = *tctx.client_context(0).private_data().my_private_key();
	auto outcome = sa->commit_block(creator_a.test_user_change());
	REQUIRE(outcome.block);
	REQUIRE(outcome.envelope);

	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);
	auto recs_b = sb->get_records(sequence_number{1}, sequence_number{1});
	REQUIRE(recs_b.size() == 1);
	CHECK(recs_b[0].tag() == creator_a.last_tag);

	{ // the origin's signed assignment is what B's log keeps
		auto envs_b = sb->get_envelopes(sequence_number{1}, sequence_number{1});
		REQUIRE(envs_b.size() == 1);
		CHECK(envs_b[0].origin() == key_a);
		CHECK(envs_b[0].is_signed());
		CHECK(!envs_b[0].verify(sid, tctx.client_context(1).public_keys()));
		CHECK(envs_b[0].block().sequence() == sequence_number{1});
	}
	{ // and the origin head advanced
		auto head = sb->origin_heads().find(key_a);
		REQUIRE(head);
		CHECK(head->block.sequence == sequence_number{1});
	}

	// a duplicate is ignored without growing the chain
	CHECK(!sb->apply_foreign(*outcome.envelope));
	CHECK(sb->current_sequence_number() == sequence_number{1});

	// concurrent commit on B: both converge to the same tag set (sequences are local, D4)
	test::test_block_creator creator_b;
	creator_b.signer = *tctx.client_context(1).private_data().my_private_key();
	REQUIRE(sb->commit_block(creator_b.test_user_change()).block);

	WAIT_CHECK(sa->current_sequence_number() == sequence_number{2}, 5s);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{2}, 5s);

	CHECK(tag_set(*sa, sequence_number{2}) == tag_set(*sb, sequence_number{2}));

	a.close();
	b.close();
	std::filesystem::remove_all("test-s2s-pa");
	std::filesystem::remove_all("test-s2s-pb");
}

// tag-bound seen rule across replicas (plan 4.3/D4): a stale client is rejected and a
// fresh one accepted on either replica, with replica-local sequences free to differ
TEST_CASE("s2s tag bound rules across replicas", "[unit]") {
	std::filesystem::remove_all("test-s2s-ta");
	std::filesystem::remove_all("test-s2s-tb");

	test::test_context tctx;
	tctx.add_client(2);
	tctx.share_client_keys();
	network::enable_pk_handshake(tctx.client_context(0));
	network::enable_pk_handshake(tctx.client_context(1));

	auto const key_a = tctx.key_id(0);
	auto const key_b = tctx.key_id(1);

	storage_server a(tctx.client_context(0),
		s2s_test_params("test-s2s-ta", 42754, 42764, {peer_config{"127.0.0.1", 42765, key_b}}));
	storage_server b(tctx.client_context(1),
		s2s_test_params("test-s2s-tb", 42755, 42765, {peer_config{"127.0.0.1", 42764, key_a}}));

	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	storage_modes const modes{sync_mode::require_special_seen, auth_mode::sign_records, replication_mode::weak};
	auto sa = a.open_storage(sid, modes);
	auto sb = b.open_storage(sid, modes);
	REQUIRE(sa);
	REQUIRE(sb);
	a.start();
	b.start();
	WAIT_CHECK((!a.connected_peers().empty() && !b.connected_peers().empty()), 5s);

	// the first special record spreads to both replicas
	test::test_block_creator client_a;
	client_a.signer = *tctx.client_context(0).private_data().my_private_key();
	REQUIRE(sa->commit_block(client_a.test_user_change()).block);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);

	auto stale = client_a;      // saw only the first special record
	auto client_b = client_a;   // a client of B with the same view
	client_b.signer = *tctx.client_context(1).private_data().my_private_key();
	auto fresh = client_a;

	// a data change lands on B, then a membership change on A; the change ends up at
	// different local sequences on the two replicas
	REQUIRE(sb->commit_block(client_b.test_data_change()).block);
	REQUIRE(sa->commit_block(fresh.test_user_change()).block);
	WAIT_CHECK(sa->current_sequence_number() == sequence_number{3}, 5s);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{3}, 5s);

	{ // the stale client is rejected on either replica
		auto on_a = stale;
		CHECK(check_result_error(sa->commit_block(on_a.test_data_change()).block, protocol::errc::record_out_of_sync));
		auto on_b = stale;
		CHECK(check_result_error(sb->commit_block(on_b.test_data_change()).block, protocol::errc::record_out_of_sync));
	}

	// the client that saw the membership change is accepted on the OTHER replica even
	// though the change sits at a different local sequence there
	REQUIRE(sb->commit_block(fresh.test_data_change()).block);
	WAIT_CHECK(sa->current_sequence_number() == sequence_number{4}, 5s);
	CHECK(tag_set(*sa, sequence_number{4}) == tag_set(*sb, sequence_number{4}));

	a.close();
	b.close();
	std::filesystem::remove_all("test-s2s-ta");
	std::filesystem::remove_all("test-s2s-tb");
}

// anti-entropy (plan 4.4): commits made while a peer is down (or partitioned away) are
// pulled on reconnect via the heads exchange, both directions, idempotently
TEST_CASE("s2s anti-entropy heals partitions", "[unit]") {
	std::filesystem::remove_all("test-s2s-ea");
	std::filesystem::remove_all("test-s2s-eb");

	test::test_context tctx;
	tctx.add_client(2);
	tctx.share_client_keys();
	network::enable_pk_handshake(tctx.client_context(0));
	network::enable_pk_handshake(tctx.client_context(1));

	auto const key_a = tctx.key_id(0);
	auto const key_b = tctx.key_id(1);

	auto params_a = s2s_test_params("test-s2s-ea", 42756, 42766, {peer_config{"127.0.0.1", 42767, key_b}});
	auto params_b = s2s_test_params("test-s2s-eb", 42757, 42767, {peer_config{"127.0.0.1", 42766, key_a}});
	params_a.anti_entropy_interval = std::chrono::seconds{1};
	params_b.anti_entropy_interval = std::chrono::seconds{1};

	storage_server a(tctx.client_context(0), params_a);
	auto b = std::make_unique<storage_server>(tctx.client_context(1), params_b);

	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	storage_modes const modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::weak};
	auto sa = a.open_storage(sid, modes);
	auto sb = b->open_storage(sid, modes);
	REQUIRE(sa);
	REQUIRE(sb);
	a.start();
	b->start();
	WAIT_CHECK((!a.connected_peers().empty() && !b->connected_peers().empty()), 5s);

	// a first record spreads while both are up
	test::test_block_creator client_a;
	client_a.signer = *tctx.client_context(0).private_data().my_private_key();
	REQUIRE(sa->commit_block(client_a.test_user_change()).block);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);

	// partition: B's server goes down; its storage keeps taking local commits
	b->close();
	test::test_block_creator client_b = client_a;
	client_b.signer = *tctx.client_context(1).private_data().my_private_key();
	REQUIRE(sa->commit_block(client_a.test_data_change()).block);
	REQUIRE(sb->commit_block(client_b.test_data_change()).block);
	CHECK(sa->current_sequence_number() == sequence_number{2});
	CHECK(sb->current_sequence_number() == sequence_number{2});

	// heal: B restarts on the same root; both directions catch up via the heads exchange
	sb.reset();
	b.reset();
	storage_server b2(tctx.client_context(1), params_b);
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
	std::filesystem::remove_all("test-s2s-ea");
	std::filesystem::remove_all("test-s2s-eb");
}


// a storage created on one replica appears on the others (the heads and pushes carry its
// modes, plan 4.2/4.4): B never opened it and gets both the storage and the record
TEST_CASE("s2s replica creates the storage on first contact", "[unit]") {
	std::filesystem::remove_all("test-s2s-ca");
	std::filesystem::remove_all("test-s2s-cb");

	test::test_context tctx;
	tctx.add_client(2);
	// no pre-shared keys: B learns A's key from the authenticated peer handshake and
	// verifies A's signed assignments (and A's signed record) with it
	network::enable_pk_handshake(tctx.client_context(0));
	network::enable_pk_handshake(tctx.client_context(1));

	auto const key_a = tctx.key_id(0);
	auto const key_b = tctx.key_id(1);

	storage_server a(tctx.client_context(0),
		s2s_test_params("test-s2s-ca", 42780, 42790, {peer_config{"127.0.0.1", 42791, key_b}}));
	storage_server b(tctx.client_context(1),
		s2s_test_params("test-s2s-cb", 42781, 42791, {peer_config{"127.0.0.1", 42790, key_a}}));

	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	storage_modes const modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::weak};
	auto sa = a.open_storage(sid, modes);
	REQUIRE(sa);
	a.start();
	b.start();
	WAIT_CHECK((!a.connected_peers().empty() && !b.connected_peers().empty()), 5s);

	// an unreplicated storage is never created by a peer's announcement
	protocol::storage_id const local_sid = securepath::test::random_octet_vector(8);
	REQUIRE(a.open_storage(local_sid, storage_modes{sync_mode::allow_all, auth_mode::sign_records}));

	test::test_block_creator creator_a;
	creator_a.signer = *tctx.client_context(0).private_data().my_private_key();
	REQUIRE(sa->commit_block(creator_a.test_user_change()).block);

	WAIT_CHECK(b.has_storage(sid), 5s);
	auto sb = b.open_storage(sid, modes);
	REQUIRE(sb);
	CHECK(sb->modes() == sa->modes());   // incl. the limits A filled from its defaults
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);
	CHECK(!b.has_storage(local_sid));

	a.close();
	b.close();
	std::filesystem::remove_all("test-s2s-ca");
	std::filesystem::remove_all("test-s2s-cb");
}

// a restarted server reopens its replicated storages from disk (plan 5.1): nobody has to
// connect to it before it announces heads, takes pushes and serves pulls again
TEST_CASE("s2s restart reopens replicated storages", "[unit]") {
	std::filesystem::remove_all("test-s2s-ra");
	std::filesystem::remove_all("test-s2s-rb");

	test::test_context tctx;
	tctx.add_client(2);
	tctx.share_client_keys();
	network::enable_pk_handshake(tctx.client_context(0));
	network::enable_pk_handshake(tctx.client_context(1));

	auto const key_a = tctx.key_id(0);
	auto const key_b = tctx.key_id(1);
	auto const params_a = s2s_test_params("test-s2s-ra", 42782, 42792, {peer_config{"127.0.0.1", 42793, key_b}});
	auto const params_b = s2s_test_params("test-s2s-rb", 42783, 42793, {peer_config{"127.0.0.1", 42792, key_a}});

	protocol::storage_id const sid = securepath::test::random_octet_vector(8);
	storage_modes const modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::weak};
	test::test_block_creator creator_a;
	creator_a.signer = *tctx.client_context(0).private_data().my_private_key();
	{
		// A holds the storage with one record and goes down
		storage_server a(tctx.client_context(0), params_a);
		auto sa = a.open_storage(sid, modes);
		REQUIRE(sa);
		REQUIRE(sa->commit_block(creator_a.test_user_change()).block);
		a.close();
	}

	storage_server b(tctx.client_context(1), params_b);
	b.start();
	storage_server a(tctx.client_context(0), params_a);
	a.start();
	WAIT_CHECK((!a.connected_peers().empty() && !b.connected_peers().empty()), 5s);

	// A announced the storage it reopened: B created its replica and pulled the record
	WAIT_CHECK(b.has_storage(sid), 5s);
	auto sb = b.open_storage(sid, modes);
	REQUIRE(sb);
	WAIT_CHECK(sb->current_sequence_number() == sequence_number{1}, 5s);

	// and a push from B lands in A's reopened storage without any client opening it
	test::test_block_creator creator_b = creator_a;
	creator_b.signer = *tctx.client_context(1).private_data().my_private_key();
	REQUIRE(sb->commit_block(creator_b.test_data_change()).block);
	auto sa = a.open_storage(sid, modes);
	REQUIRE(sa);
	WAIT_CHECK(sa->current_sequence_number() == sequence_number{2}, 5s);

	a.close();
	b.close();
	std::filesystem::remove_all("test-s2s-ra");
	std::filesystem::remove_all("test-s2s-rb");
}


// (plan 5.2) a new replica joins a running cluster: it learns every replicated storage
// from the heads its peers announce, pulls every origin from the start, verifies the
// origins' assignments and the clients' signatures - fetching the key of a signer it
// never saw from the peer that holds the record - and reports syncing until caught up
TEST_CASE("s2s bootstrap a new replica", "[unit]") {
	for(auto d : {"test-s2s-ba", "test-s2s-bb", "test-s2s-bc"}) {
		std::filesystem::remove_all(d);
	}

	test::test_context tctx;
	tctx.add_client(4);   // 0 = A, 1 = B, 2 = C (the newcomer), 3 = a client that registered at A and B
	for(int i = 0; i != 3; ++i) {
		network::enable_pk_handshake(tctx.client_context(i));
	}
	auto const key_a = tctx.key_id(0);
	auto const key_b = tctx.key_id(1);
	auto const key_c = tctx.key_id(2);
	auto const client_key = *tctx.client_context(3).private_data().my_private_key();
	tctx.client_context(0).public_keys().insert(client_key.public_key());
	tctx.client_context(1).public_keys().insert(client_key.public_key());

	auto params_a = s2s_test_params("test-s2s-ba", 42784, 42794,
		{peer_config{"127.0.0.1", 42795, key_b}, peer_config{"127.0.0.1", 42796, key_c}});
	auto params_b = s2s_test_params("test-s2s-bb", 42785, 42795,
		{peer_config{"127.0.0.1", 42794, key_a}, peer_config{"127.0.0.1", 42796, key_c}});
	auto params_c = s2s_test_params("test-s2s-bc", 42786, 42796,
		{peer_config{"127.0.0.1", 42794, key_a}, peer_config{"127.0.0.1", 42795, key_b}});
	for(auto p : {&params_a, &params_b, &params_c}) {
		p->anti_entropy_interval = std::chrono::seconds{1};
	}

	storage_server a(tctx.client_context(0), params_a);
	storage_server b(tctx.client_context(1), params_b);
	storage_modes const modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::weak};
	protocol::storage_id const sid1 = securepath::test::random_octet_vector(8);
	protocol::storage_id const sid2 = securepath::test::random_octet_vector(8);
	protocol::storage_id const local_sid = securepath::test::random_octet_vector(8);
	auto sa1 = a.open_storage(sid1, modes);
	auto sb1 = b.open_storage(sid1, modes);
	auto sa2 = a.open_storage(sid2, modes);
	auto sb2 = b.open_storage(sid2, modes);
	REQUIRE(a.open_storage(local_sid, storage_modes{sync_mode::allow_all, auth_mode::sign_records}));
	a.start();
	b.start();
	WAIT_CHECK((!a.connected_peers().empty() && !b.connected_peers().empty()), 5s);

	// records of both origins in both storages, all signed by the client
	test::test_block_creator creator1;
	creator1.signer = client_key;
	REQUIRE(sa1->commit_block(creator1.test_user_change()).block);
	REQUIRE(sa1->commit_block(creator1.test_data_change()).block);
	WAIT_CHECK(sb1->current_sequence_number() == sequence_number{2}, 5s);
	test::test_block_creator creator1b = creator1;
	REQUIRE(sb1->commit_block(creator1b.test_data_change()).block);
	WAIT_CHECK(sa1->current_sequence_number() == sequence_number{3}, 5s);
	test::test_block_creator creator2;
	creator2.signer = client_key;
	REQUIRE(sb2->commit_block(creator2.test_user_change()).block);
	WAIT_CHECK(sa2->current_sequence_number() == sequence_number{1}, 5s);

	// C joins: nothing configured on it but the peers
	storage_server c(tctx.client_context(2), params_c);
	c.start();
	WAIT_CHECK((c.has_storage(sid1) && c.has_storage(sid2)), 10s);
	auto sc1 = c.open_storage(sid1, modes);
	auto sc2 = c.open_storage(sid2, modes);
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
	for(auto d : {"test-s2s-ba", "test-s2s-bb", "test-s2s-bc"}) {
		std::filesystem::remove_all(d);
	}
}

}
