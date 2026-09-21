#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/protocol/error.hpp>
#include <spsync/util/result.hpp>
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

	// (the retention policy the server's defaults leave open is the compiled one)
	{
		storage s(sid, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records});
		CHECK(s.modes().limits == storage_limits{16 * 1024, 512 * 1024, default_kept_data_versions});
	}
	{
		storage s(sid, cfg);
		CHECK(s.modes().limits == storage_limits{16 * 1024, 512 * 1024, default_kept_data_versions});
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
		CHECK(s.modes().limits == storage_limits{64 * 1024, 1024 * 1024, default_kept_data_versions});
	}
	protocol::storage_id sid3 = securepath::test::random_octet_vector(8);
	CHECK_THROWS(storage(sid3, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records,
		replication_mode::none, storage_limits{1024, 0}}));
	CHECK_THROWS(storage(sid3, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records,
		replication_mode::none, storage_limits{0, 1024}}));

	// the biggest record a storage may allow is the biggest one the codec carries (a
	// record is one octet string of its block); the defaults are inside the ranges
	static_assert(valid_storage_limits(storage_limits{max_record_size_range.highest, chunk_size_range.highest}));
	static_assert(!valid_storage_limits(storage_limits{max_record_size_range.highest + 1, 0}));
	static_assert(!valid_storage_limits(storage_limits{0, chunk_size_range.highest + 1}));
	static_assert(valid_storage_limits(storage_limits{default_max_record_size, default_chunk_size}));
	static_assert(default_max_record_size == 1024 * 1024);
	static_assert(max_record_size_range.highest == 2 * 1024 * 1024);
	CHECK_THROWS(storage(sid3, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records,
		replication_mode::none, storage_limits{max_record_size_range.highest + 1, 0}}));
	{
		storage s(sid3, cfg, storage_modes{sync_mode::allow_all, auth_mode::sign_records,
			replication_mode::none, storage_limits{max_record_size_range.highest, 0}});
		CHECK(s.modes().limits.max_record_size == max_record_size_range.highest);
	}

	std::filesystem::remove_all(root);
}

// (RDS 9) the retention policy at a history cut is a creation parameter like the limits
TEST_CASE("storage retention policy is persisted and immutable", "[unit]") {
	std::string const root = "test-storage-root-retention";
	std::filesystem::remove_all(root);
	storage_config cfg{root};
	auto const modes = [](std::uint32_t kept) {
		return storage_modes{sync_mode::allow_all, auth_mode::sign_records, replication_mode::none, storage_limits{0, 0, kept}};
	};
	static_assert(default_kept_data_versions == 1);
	static_assert(default_storage_limits.kept_data_versions == default_kept_data_versions);
	static_assert(valid_storage_limits(storage_limits{0, 0, keep_all_data_versions}));
	static_assert(valid_storage_limits(default_storage_limits));
	static_assert(modes_match(storage_modes{}, storage_modes{sync_mode::require_all_seen, auth_mode::only_tag, replication_mode::none, default_storage_limits}));
	static_assert(limits_or(storage_limits{1, 0, 3}, storage_limits{7, 8, 9}) == storage_limits{1, 8, 3});

	// the newest version only, unless the server's defaults or the creation say otherwise
	protocol::storage_id const plain = securepath::test::random_octet_vector(8);
	CHECK(storage(plain, cfg, modes(0)).modes().limits.kept_data_versions == 1);

	cfg.set_default_limits(storage_limits{0, 0, 5});
	protocol::storage_id const by_default = securepath::test::random_octet_vector(8);
	CHECK(storage(by_default, cfg, modes(0)).modes().limits.kept_data_versions == 5);
	CHECK(storage(plain, cfg).modes().limits.kept_data_versions == 1);

	protocol::storage_id const stated = securepath::test::random_octet_vector(8);
	CHECK(storage(stated, cfg, modes(keep_all_data_versions)).modes().limits.kept_data_versions == keep_all_data_versions);
	CHECK(storage(stated, cfg).modes().limits.kept_data_versions == keep_all_data_versions);
	CHECK_NOTHROW(storage(stated, cfg, modes(keep_all_data_versions)));
	CHECK_NOTHROW(storage(stated, cfg, modes(0)));
	CHECK_THROWS(storage(stated, cfg, modes(2)));

	// a storage from before the policy was promised nothing else than that data lives as
	// long as its record
	database::sqlite::create_sqlite_connection(root + "/" + to_hex(plain) + "/storage.db")
		->prepare("ALTER TABLE storage_config DROP COLUMN kept_data_versions;").execute();
	CHECK(storage(plain, cfg).modes().limits.kept_data_versions == keep_all_data_versions);

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

// (RDS 5) what a data ticket is issued from: the descriptor of a data a committed record names
TEST_CASE("storage committed data", "[unit]") {
	std::string const root = "test-storage-root";
	std::filesystem::remove_all(root);
	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage s(sid, storage_config{root}, storage_modes{sync_mode::allow_all, auth_mode::only_tag});

	test::test_block_creator creator;
	REQUIRE(s.commit_block(creator.test_user_change()).block);

	data_descriptor const committed{3 * 1024 * 1024 + 48, 1024 * 1024, securepath::test::random_octet_vector(64)};
	CHECK(!s.committed_data(committed.manifest_digest));
	REQUIRE(s.commit_block(creator.test_data_change_with_data(committed)).block);
	CHECK(s.committed_data(committed.manifest_digest).value() == committed);

	// a refused record names nothing
	data_descriptor const refused{4112, 100, securepath::test::random_octet_vector(64)};
	CHECK(!s.commit_block(creator.test_data_change_with_data(refused)).block);
	CHECK(!s.committed_data(refused.manifest_digest));
	CHECK(!s.committed_data(securepath::test::random_octet_vector(64)));
	CHECK(!s.committed_data({}));
}

// (RDS 9) record data follows its records: a history cut keeps the data of the records it
// retains - today that is every object's whole chain - a rollback releases the data of
// the records it takes, unless a record that stays names the same data
TEST_CASE("storage releases the data of removed records", "[unit]") {
	std::string const root = "test-storage-root";
	std::filesystem::remove_all(root);
	protocol::storage_id sid = securepath::test::random_octet_vector(8);
	storage s(sid, storage_config{root}, storage_modes{sync_mode::allow_all, auth_mode::only_tag});

	std::vector<std::pair<protocol::storage_id, std::vector<data_id>>> released;
	s.set_data_release([&](protocol::storage_id const& id, std::vector<data_id> const& ids) {
		// called without the storage's mutex (asking it back would never return) and
		// after the index forgot the data
		for(auto const& dead : ids) {
			CHECK(!s.committed_data(dead));
		}
		released.emplace_back(id, ids);
	});

	auto const descriptor = [] {
		return data_descriptor{3 * 1024 * 1024 + 48, 1024 * 1024, securepath::test::random_octet_vector(64)};
	};
	auto const first = descriptor();
	auto const second = descriptor();
	auto const shared = descriptor();
	auto const late = descriptor();

	test::test_block_creator creator;
	REQUIRE(s.commit_block(creator.test_user_change()).block);
	auto const object = creator.test_data_change_with_data(first);
	REQUIRE(s.commit_block(object).block);
	REQUIRE(s.commit_block(creator.test_data_change_with_data(second)).block);
	REQUIRE(s.commit_block(creator.test_data_change_with_data(shared)).block);
	auto const segment = creator.test_segment(plain_segment_data{sequence_number{1}, sequence_number{5}, creator.created_tags});
	REQUIRE(s.commit_block(segment).block);
	auto const after_cut = creator.test_data_change_with_data(shared);
	REQUIRE(s.commit_block(after_cut).block);
	REQUIRE(s.commit_block(creator.test_data_change_with_data(late)).block);

	// the cut takes the root user change; every object is live, so is every data
	auto const cut = s.cut_history(segment.tag());
	CHECK(cut.size() == 1);
	CHECK(released.empty());
	for(auto const& d : {first, second, shared, late}) {
		CHECK(s.committed_data(d.manifest_digest).value() == d);
	}

	// the rollback takes the last record: its data is named by nobody any more
	auto rolled_back = s.truncate_from(sequence_number{7});
	CHECK(rolled_back.size() == 1);
	REQUIRE(released.size() == 1);
	CHECK(released[0].first == sid);
	CHECK(released[0].second == std::vector<data_id>{late.manifest_digest});
	CHECK(!s.committed_data(late.manifest_digest));

	// the next one names a data that a record below the cut names too: it stays
	rolled_back = s.truncate_from(sequence_number{6});
	CHECK(rolled_back.size() == 1);
	CHECK(released.size() == 1);
	CHECK(s.committed_data(shared.manifest_digest).value() == shared);

	// nothing to release, nothing told
	CHECK(s.truncate_from(sequence_number{100}).empty());
	CHECK(released.size() == 1);
}

// (RDS 9) the retention policy at a cut: the records of superseded versions stay, their
// data goes - no tickets for it any more, the data servers are told
TEST_CASE("storage prunes the data of superseded versions at a cut", "[unit]") {
	std::string const root = "test-storage-root";
	std::filesystem::remove_all(root);
	auto const descriptor = [] {
		return data_descriptor{3 * 1024 * 1024 + 48, 1024 * 1024, securepath::test::random_octet_vector(64)};
	};
	auto const d1 = descriptor(), d2 = descriptor(), d3 = descriptor(), other = descriptor();
	auto const oid = util::create_object_id();

	struct history {
		chain_block v1, segment;
	};
	auto const fill = [&](storage& s, test::test_block_creator& creator) {
		REQUIRE(s.commit_block(creator.test_user_change()).block);
		auto const v1 = creator.test_versions({{oid, {}, d1}});
		REQUIRE(s.commit_block(v1).block);
		auto const v2 = creator.test_versions({{oid, v1.tag(), d2}});
		REQUIRE(s.commit_block(v2).block);
		REQUIRE(s.commit_block(creator.test_data_change_with_data(other)).block);
		auto const segment = creator.test_segment(plain_segment_data{sequence_number{1}, sequence_number{5}, creator.created_tags});
		REQUIRE(s.commit_block(segment).block);
		REQUIRE(s.commit_block(creator.test_versions({{oid, v2.tag(), d3}})).block);
		return history{v1, segment};
	};

	SECTION("the newest version only") {
		protocol::storage_id sid = securepath::test::random_octet_vector(8);
		storage s(sid, storage_config{root}, storage_modes{sync_mode::allow_all, auth_mode::only_tag});
		REQUIRE(s.modes().limits.kept_data_versions == 1);
		std::vector<std::vector<data_id>> released;
		s.set_data_release([&](protocol::storage_id const&, std::vector<data_id> const& ids) {
			for(auto const& id : ids) {
				CHECK(check_result_error(s.committed_data(id), protocol::errc::data_pruned));
			}
			released.push_back(ids);
		});
		test::test_block_creator creator;
		auto const made = fill(s, creator);

		// the cut removes the root user change, the versions of the object all stay
		CHECK(s.cut_history(made.segment.tag()).size() == 1);
		REQUIRE(released.size() == 1);
		CHECK(released[0] == std::vector<data_id>{d1.manifest_digest});
		// d2 is the newest below the segment; d3 above it supersedes nothing yet
		for(auto const& d : {d2, d3, other}) {
			CHECK(s.committed_data(d.manifest_digest).value() == d);
		}
		CHECK(check_result_error(s.committed_data(d1.manifest_digest), protocol::errc::data_pruned));
		CHECK(s.get_records(made.v1.sequence(), made.v1.sequence()).size() == 1);

		// a record that names the data again wants it again
		REQUIRE(s.commit_block(creator.test_data_change_with_data(d1)).block);
		CHECK(s.committed_data(d1.manifest_digest).value() == d1);
	}

	SECTION("a storage that keeps every version") {
		protocol::storage_id sid = securepath::test::random_octet_vector(8);
		storage s(sid, storage_config{root}, storage_modes{sync_mode::allow_all, auth_mode::only_tag
			, replication_mode::none, storage_limits{0, 0, keep_all_data_versions}});
		bool released = false;
		s.set_data_release([&](protocol::storage_id const&, std::vector<data_id> const&) { released = true; });
		test::test_block_creator creator;
		auto const made = fill(s, creator);
		CHECK(s.cut_history(made.segment.tag()).size() == 1);
		CHECK(!released);
		CHECK(s.committed_data(d1.manifest_digest).value() == d1);
	}
}

}
