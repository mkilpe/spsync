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

}
