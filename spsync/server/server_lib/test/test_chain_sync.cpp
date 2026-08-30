#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <spsync/protocol/error.hpp>
#include <spsync/server/server_lib/chain_sync.hpp>

#include <spsync/test/test_block_creator.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>

// + (1) basic test for committing with 'all seen' mode
// + (2) basic test for committing with 'allow all' mode
// + (3) basic test for committing with 'require special' mode
// + (4) basic test for committing with 'require object add/remove' mode

namespace securepath::sync {

using test::test_block_creator;
std::string const db_name = "record_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

// (1) basic test for committing with 'all seen' mode
TEST_CASE("chain_sync require all config", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_all_seen});

	test_block_creator creator;
	auto rec = creator.test_user_change();

	// commit first block
	CHECK(sync.commit_block(rec));
	CHECK(check_result_error(sync.commit_block(rec), protocol::errc::record_already_committed));

	auto creator_copy{creator};
	CHECK(sync.commit_block(creator.test_user_change()));
	CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));

	auto dchange = creator.test_data_change();
	CHECK(sync.commit_block(dchange));
	CHECK(sync.commit_block(creator.test_followup_data_change(dchange)));

	CHECK(sync.current_sequence_number() == creator.last_server_seq);

	{
		auto creator_copy{creator};
		// using same previous oid record tag, which should error out
		CHECK(check_result_error(sync.commit_block(creator_copy.test_followup_data_change(dchange)), protocol::errc::record_out_of_sync));
	}
	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_data_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_data_change()), protocol::errc::record_out_of_sync));
	}

	CHECK(sync.current_sequence_number() == creator.last_server_seq);
	CHECK(sync.get_records(sequence_number{1}, creator.last_server_seq+1).size() == creator.last_server_seq.value);
	CHECK(sync.get_records(sequence_number{1}, sequence_number{100}).size() == creator.last_server_seq.value);
}

// (2) basic test for committing with 'allow all' mode
TEST_CASE("chain_sync allow all config", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::allow_all});

	test_block_creator creator;
	auto rec = creator.test_user_change();

	// commit first block
	CHECK(sync.commit_block(rec));
	CHECK(check_result_error(sync.commit_block(rec), protocol::errc::record_already_committed));

	auto creator_copy{creator};
	CHECK(sync.commit_block(creator.test_user_change()));
	CHECK(sync.commit_block(creator_copy.test_user_change()));

	auto dchange = creator.test_data_change();
	CHECK(sync.commit_block(dchange));
	CHECK(sync.commit_block(creator.test_followup_data_change(dchange)));

	// using same previous oid record tag, which should error out
	CHECK(check_result_error(sync.commit_block(creator.test_followup_data_change(dchange)), protocol::errc::record_out_of_sync));

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_data_change()));
		CHECK(sync.commit_block(creator_copy.test_data_change()));
	}
}

// (3) basic test for committing with 'require special' mode
TEST_CASE("chain_sync require special config", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});

	test_block_creator creator;
	auto rec = creator.test_user_change();

	// commit first block
	CHECK(sync.commit_block(rec));
	CHECK(check_result_error(sync.commit_block(rec), protocol::errc::record_already_committed));

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));
	}

	auto dchange = creator.test_data_change();
	CHECK(sync.commit_block(dchange));
	CHECK(sync.commit_block(creator.test_followup_data_change(dchange)));

	// using same previous oid record tag, which should error out
	CHECK(check_result_error(sync.commit_block(creator.test_followup_data_change(dchange)), protocol::errc::record_out_of_sync));

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_data_change()));
		CHECK(sync.commit_block(creator_copy.test_data_change()));
	}
	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));
	}
}

// (4) basic test for committing with 'require object add/remove' mode
TEST_CASE("chain_sync require data add remove config", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_data_add_remove_seen});

	test_block_creator creator;
	auto rec = creator.test_user_change();

	// commit first block
	CHECK(sync.commit_block(rec));
	CHECK(check_result_error(sync.commit_block(rec), protocol::errc::record_already_committed));

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));
	}

	auto dchange = creator.test_data_change();
	CHECK(sync.commit_block(dchange));
	CHECK(sync.commit_block(creator.test_followup_data_change(dchange)));

	{
		auto creator_copy{creator};
		// using same previous oid record tag, which should error out
		CHECK(check_result_error(sync.commit_block(creator_copy.test_followup_data_change(dchange)), protocol::errc::record_out_of_sync));
	}

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_data_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_data_change()), protocol::errc::record_out_of_sync));
	}

	auto change1 = creator.test_data_change();
	CHECK(sync.commit_block(change1));
	auto change2 = creator.test_data_change();
	CHECK(sync.commit_block(change2));
	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_followup_data_change(change1)));
		CHECK(sync.commit_block(creator_copy.test_followup_data_change(change2)));
	}
	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));
	}
}



// (5) mode cursors are replayed from the database on reopen (defect B1)
TEST_CASE("chain_sync special cursor replay on reopen", "[unit]") {
	remove_database_test_db();
	test_block_creator creator;
	test_block_creator stale;
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});
		CHECK(sync.commit_block(creator.test_user_change()));
		stale = creator; // has seen only the first special record
		CHECK(sync.commit_block(creator.test_user_change()));
	}
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});
		CHECK(sync.current_sequence_number() == creator.last_server_seq);
		// a client that has not seen the newest special record must still be rejected after restart
		CHECK(check_result_error(sync.commit_block(stale.test_user_change()), protocol::errc::record_out_of_sync));
		CHECK(sync.commit_block(creator.test_data_change()));
	}
}

// (6) data add cursor is replayed from the database on reopen (defect B1)
TEST_CASE("chain_sync data add cursor replay on reopen", "[unit]") {
	remove_database_test_db();
	test_block_creator creator;
	test_block_creator stale;
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_data_add_remove_seen});
		CHECK(sync.commit_block(creator.test_user_change()));
		stale = creator; // has seen only the first record
		CHECK(sync.commit_block(creator.test_data_change()));
	}
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_data_add_remove_seen});
		// a client that has not seen the add at seq 2 must still be rejected after restart
		CHECK(check_result_error(sync.commit_block(stale.test_data_change()), protocol::errc::record_out_of_sync));
		CHECK(sync.commit_block(creator.test_data_change()));
	}
}

// (6b) truncation: head and mode cursors are re-derived after truncate_from (plan 3.1/3.2)
TEST_CASE("chain_sync truncate then recommit", "[unit]") {
	remove_database_test_db();
	test_block_creator creator;
	test_block_creator snapshot;
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});
		CHECK(sync.commit_block(creator.test_user_change()));
		snapshot = creator; // has seen only the first special record
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(sync.commit_block(creator.test_data_change()));

		auto removed = sync.truncate_from(sequence_number{2});
		REQUIRE(removed.size() == 2);
		CHECK(removed[0].sequence() == sequence_number{2});
		CHECK(removed[1].sequence() == sequence_number{3});

		// head and mode cursors are re-derived live, no reopen needed
		CHECK(sync.current_sequence_number() == sequence_number{1});
		auto recommit = snapshot;
		CHECK(sync.commit_block(recommit.test_user_change()));
		CHECK(sync.current_sequence_number() == sequence_number{2});
	}
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});
		CHECK(sync.current_sequence_number() == sequence_number{2});
		// a client that saw only the first special record is behind the recommitted one
		creator = snapshot;
		CHECK(check_result_error(sync.commit_block(creator.test_user_change()), protocol::errc::record_out_of_sync));
	}
}

// (7) validate/apply split behaves like commit_block
TEST_CASE("chain_sync validate and apply", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_all_seen});

	test_block_creator creator;
	auto b1 = creator.test_user_change();
	CHECK(!sync.validate(b1));
	auto committed = sync.apply(b1);
	CHECK(committed.sequence() == sequence_number{1});
	CHECK(sync.current_sequence_number() == sequence_number{1});

	// after apply the same block is a duplicate
	CHECK(bool(sync.validate(b1)));
	CHECK(check_result_error(sync.commit_block(b1), protocol::errc::record_already_committed));

	auto b2 = creator.test_data_change();
	CHECK(!sync.validate(b2));
	CHECK(sync.commit_block(b2));
}


// (8) a rebased duplicate (same op id, different tag) of a committed record is rejected
TEST_CASE("chain_sync op id dedup", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::allow_all});

	test_block_creator creator;
	CHECK(sync.commit_block(creator.test_user_change()));

	auto op = securepath::test::random_octet_vector(16);
	creator.force_op_id = op;
	CHECK(sync.commit_block(creator.test_data_change()));

	// the "rebased" form: same operation id, everything else fresh
	creator.force_op_id = op;
	CHECK(check_result_error(sync.commit_block(creator.test_data_change()), protocol::errc::record_already_committed));

	// a fresh operation is fine
	CHECK(sync.commit_block(creator.test_data_change()));
}


// (9) signature verification under sign_records (plan 2.3, defect B7)
TEST_CASE("chain_sync signature verification", "[unit]") {
	remove_database_test_db();
	crypto::public_key_cache keys;
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name),
		chain_sync_config{sync_mode::allow_all, auth_mode::sign_records}, &keys);

	test_block_creator creator;

	// an unsigned record is rejected
	CHECK(check_result_error(sync.commit_block(creator.test_user_change()), protocol::errc::invalid_record));

	// a signer the server does not know is rejected
	auto key = crypto::generate_private_key();
	creator.signer = key;
	CHECK(check_result_error(sync.commit_block(creator.test_user_change()), protocol::errc::unknown_signer));

	// after the key is registered the records are accepted
	keys.insert(key.public_key());
	CHECK(sync.commit_block(creator.test_user_change()));
	CHECK(sync.commit_block(creator.test_data_change()));

	// a signature transplanted from another record must not verify
	auto b1 = creator.test_data_change();
	auto b2 = creator.test_data_change();
	auto transplanted = b2.to_auth_record<data_change_record>();
	transplanted.auth = b1.auth();
	CHECK(check_result_error(sync.commit_block(chain_block{transplanted}), protocol::errc::invalid_record));
}

}
