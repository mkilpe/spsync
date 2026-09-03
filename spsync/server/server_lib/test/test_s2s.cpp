#include <spsync/test/test_context.hpp>

#include <spsync/server/server_lib/storage_server.hpp>
#include <spsync/server/server_lib/storage.hpp>

#include <spsync/test/test_block_creator.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

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

	auto heads_on_b = b.heads_of_peer(key_a, sid);
	REQUIRE(heads_on_b.size() == 1);
	CHECK(heads_on_b[0].origin == key_a);
	CHECK(heads_on_b[0].term == 0);
	CHECK(heads_on_b[0].block.sequence == sequence_number{1});
	CHECK(heads_on_b[0].block.hash == creator_a.last_chain_hash);

	auto heads_on_a = a.heads_of_peer(key_b, sid);
	REQUIRE(heads_on_a.size() == 1);
	CHECK(heads_on_a[0].origin == key_b);
	CHECK(heads_on_a[0].block.sequence == sequence_number{1});

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

	auto tag_set = [](storage& s) {
		std::vector<octet_vector> tags;
		for(auto const& r : s.get_records(sequence_number{1}, sequence_number{2})) {
			tags.push_back(r.tag());
		}
		std::ranges::sort(tags);
		return tags;
	};
	CHECK(tag_set(*sa) == tag_set(*sb));

	a.close();
	b.close();
	std::filesystem::remove_all("test-s2s-pa");
	std::filesystem::remove_all("test-s2s-pb");
}

}
