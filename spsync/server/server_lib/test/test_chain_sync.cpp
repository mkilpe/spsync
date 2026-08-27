#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <spsync/protocol/error.hpp>
#include <spsync/server/server_lib/chain_sync.hpp>

#include <spsync/test/test_block_creator.hpp>

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

}
