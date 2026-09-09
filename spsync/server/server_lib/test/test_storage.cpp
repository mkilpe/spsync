#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/protocol/error.hpp>
#include <spsync/server/server_lib/storage.hpp>
#include <spsync/test/test_block_creator.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/private_data_cache.hpp>
#include <securepath/crypto/public_key_cache.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/conversions.hpp>

#include <filesystem>

namespace securepath::sync {

TEST_CASE("storage modes are persisted and immutable", "[unit]") {
	std::string const root = "test-storage-root";
	std::filesystem::remove_all(root);
	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage_config cfg{root};

	{
		storage s(sid, cfg, storage_modes{sync_mode::require_special_seen, auth_mode::only_tag});
		CHECK(s.modes().mode == sync_mode::require_special_seen);
		CHECK(s.modes().auth == auth_mode::only_tag);
	}
	{
		// reopen without a request: the persisted modes are used
		storage s(sid, cfg);
		CHECK(s.modes().mode == sync_mode::require_special_seen);
	}
	{
		// reopen with the same requested modes is fine
		storage s(sid, cfg, storage_modes{sync_mode::require_special_seen, auth_mode::only_tag});
		CHECK(s.modes().mode == sync_mode::require_special_seen);
	}
	// requesting different modes for an existing storage must fail
	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::require_all_seen, auth_mode::only_tag}));
	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::require_special_seen, auth_mode::sign_records}));

	std::filesystem::remove_all(root);
}


// (RDS 8) validity limits are creation parameters: filled from the server defaults when
// not stated, persisted, immutable; stated limits must be in range
TEST_CASE("storage limits are persisted and immutable", "[unit]") {
	std::string const root = "test-storage-root-limits";
	std::filesystem::remove_all(root);
	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage_config cfg{root};
	cfg.set_default_limits(storage_limits{16 * 1024, 512 * 1024});

	{
		storage s(sid, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records});
		CHECK(s.modes().limits == storage_limits{16 * 1024, 512 * 1024});
	}
	{
		storage s(sid, cfg);
		CHECK(s.modes().limits == storage_limits{16 * 1024, 512 * 1024});
	}
	// stating the persisted limits (or none) is fine, different ones are a mismatch
	CHECK_NOTHROW(storage(sid, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records,
		replication_mode::none, storage_limits{16 * 1024, 512 * 1024}}));
	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records,
		replication_mode::none, storage_limits{32 * 1024, 0}}));

	// stated limits are kept; out of range ones are refused
	protocol::storage_id sid2 = securepath::test::random_octet_vector(8);
	{
		storage s(sid2, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records,
			replication_mode::none, storage_limits{64 * 1024, 1024 * 1024}});
		CHECK(s.modes().limits == storage_limits{64 * 1024, 1024 * 1024});
	}
	protocol::storage_id sid3 = securepath::test::random_octet_vector(8);
	CHECK_THROWS(storage(sid3, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records,
		replication_mode::none, storage_limits{1024, 0}}));
	CHECK_THROWS(storage(sid3, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records,
		replication_mode::none, storage_limits{0, 1024}}));

	std::filesystem::remove_all(root);
}

TEST_CASE("replicated storage requires signed records", "[unit]") {
	std::string const root = "test-storage-root-repl";
	std::filesystem::remove_all(root);
	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage_config cfg{root};

	// replication without signing is refused
	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::require_all_seen, auth_mode::only_tag, replication_mode::weak}));

	// with signing it is fine and the replication mode is persisted
	{
		storage s(sid, cfg, storage_modes{sync_mode::require_all_seen, auth_mode::sign_records, replication_mode::weak});
		CHECK(s.modes().replication == replication_mode::weak);
	}
	{
		storage s(sid, cfg);
		CHECK(s.modes().replication == replication_mode::weak);
		CHECK(s.modes().auth == auth_mode::sign_records);
	}
	// a different replication mode for an existing storage is a mismatch
	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::require_all_seen, auth_mode::sign_records, replication_mode::strict}));

	std::filesystem::remove_all(root);
}

// a refused creation leaves no database behind, and a database without persisted modes
// is not a storage: neither turns into a default mode storage on a later load
TEST_CASE("storage refused creation leaves nothing behind", "[unit]") {
	std::string const root = "test-storage-root-refused";
	std::filesystem::remove_all(root);
	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage_config cfg{root};

	CHECK_THROWS(storage(sid, cfg, storage_modes{sync_mode::require_all_seen, auth_mode::only_tag, replication_mode::weak}));
	CHECK(!std::filesystem::exists(root + "/" + to_hex(sid)));
	CHECK_THROWS(storage(sid, cfg));

	// an empty database (a creation that died before persisting its modes)
	std::filesystem::create_directories(root + "/" + to_hex(sid));
	database::sqlite::create_sqlite_connection(root + "/" + to_hex(sid) + "/storage.db");
	CHECK_THROWS(storage(sid, cfg));
	// a creation completes it
	CHECK_NOTHROW(storage(sid, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records}));
	CHECK_NOTHROW(storage(sid, cfg));

	std::filesystem::remove_all(root);
}


TEST_CASE("storage signs the sequence assignment", "[unit]") {
	std::string const root = "test-storage-root-env";
	std::filesystem::remove_all(root);
	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage_config cfg{root};

	crypto::public_key_cache keys;
	crypto::private_data_cache pdata;
	auto server_key = crypto::generate_private_key();
	pdata.set_my_private_key(server_key);
	keys.insert(server_key.public_key());

	storage s(sid, cfg, storage_modes{}, &keys, &pdata);
	test::test_block_creator creator;
	auto outcome = s.commit_block(creator.test_user_change());
	REQUIRE(outcome.block);
	REQUIRE(outcome.envelope);
	CHECK(outcome.envelope->is_signed());
	CHECK(outcome.envelope->origin() == server_key.id());
	CHECK(!outcome.envelope->verify(sid, keys));

	{ // the signed assignment is persisted in the server log (plan 3.2)
		chain_log log(database::sqlite::create_sqlite_connection(root + "/" + to_hex(sid) + "/storage.db"));
		auto envs = log.get({}, {}, 10);
		REQUIRE(envs.size() == 1);
		CHECK(envs[0].is_signed());
		CHECK(!envs[0].verify(sid, keys));
		CHECK(envs[0].block().id() == outcome.block.value().id());
	}

	{ // the anti-entropy heads: the own live head plus stored foreign origins (plan 3.4)
		auto own = origin_head{server_key.id(), 0, outcome.block.value().id()};
		CHECK(s.heads() == std::vector{own});

		auto const foreign = origin_head{crypto::public_key_id{octet_vector(32, 7)}, 0
			, chain_block_id{5, securepath::test::random_octet_vector(16)}};
		CHECK(s.origin_heads().advance(foreign));
		CHECK(s.heads() == std::vector{own, foreign});

		// the own head follows the log live
		auto outcome_next = s.commit_block(creator.test_user_change());
		REQUIRE(outcome_next.block);
		own.block = outcome_next.block.value().id();
		CHECK(s.heads() == std::vector{own, foreign});
	}

	// without a signing key there is no envelope (fresh chain, fresh creator)
	std::filesystem::remove_all(root);
	CHECK_THROWS(storage(sid, cfg));   // a load never creates
	storage s2(sid, cfg, storage_modes{});
	test::test_block_creator creator2;
	auto outcome2 = s2.commit_block(creator2.test_user_change());
	REQUIRE(outcome2.block);
	CHECK(!outcome2.envelope);
	// and no own identity to exchange
	CHECK(s2.heads().empty());

	std::filesystem::remove_all(root);
}


// a foreign record our rules refuse for good (here: over this replica's record limit) is
// skipped and the origin head moves past it, so anti-entropy carries on with the next
// record instead of re-pulling it forever and keeping the storage "syncing"
TEST_CASE("storage skips a permanently rejected foreign record", "[unit]") {
	// two replicas of the same storage, each with its own root
	std::string const root_a = "test-storage-root-skip-a";
	std::string const root_b = "test-storage-root-skip-b";
	std::filesystem::remove_all(root_a);
	std::filesystem::remove_all(root_b);
	storage_config cfg_a{root_a};
	storage_config cfg_b{root_b};

	crypto::public_key_cache keys;
	crypto::private_data_cache pdata_a;
	crypto::private_data_cache pdata_b;
	auto key_a = crypto::generate_private_key();
	auto key_b = crypto::generate_private_key();
	auto client_key = crypto::generate_private_key();
	pdata_a.set_my_private_key(key_a);
	pdata_b.set_my_private_key(key_b);
	keys.insert(key_a.public_key());
	keys.insert(key_b.public_key());
	keys.insert(client_key.public_key());

	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage a(sid, cfg_a, storage_modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::weak,
		storage_limits{64 * 1024, 0}}, &keys, &pdata_a);
	storage b(sid, cfg_b, storage_modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::weak,
		storage_limits{4 * 1024, 0}}, &keys, &pdata_b);

	test::test_block_creator creator;
	creator.signer = client_key;
	auto first = a.commit_block(creator.test_user_change());
	REQUIRE(first.envelope);
	CHECK(!b.apply_foreign(*first.envelope));
	CHECK(b.current_sequence_number() == sequence_number{1});

	// too big for B: skipped, head advanced, nothing stored
	auto big = a.commit_block(creator.test_multi_data_change(400));
	REQUIRE(big.envelope);
	CHECK(!b.apply_foreign(*big.envelope));
	CHECK(b.current_sequence_number() == sequence_number{1});
	CHECK(b.known_origin_seq(key_a.id()) == sequence_number{2});

	// the next record still lands
	auto next = a.commit_block(creator.test_data_change());
	REQUIRE(next.envelope);
	CHECK(!b.apply_foreign(*next.envelope));
	CHECK(b.current_sequence_number() == sequence_number{2});
	CHECK(b.known_origin_seq(key_a.id()) == sequence_number{3});

	std::filesystem::remove_all(root_a);
	std::filesystem::remove_all(root_b);
}

}
