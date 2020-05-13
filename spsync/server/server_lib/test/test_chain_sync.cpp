#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <spsync/protocol/error.hpp>
#include <spsync/server/server_lib/chain_sync.hpp>

#include <spsync/test/test_block_creator.hpp>

namespace securepath::sync {

using test::test_block_creator;
std::string const db_name = "record_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

/*
enum class sync_mode {
	allow_all,
	require_special_seen,
	require_data_add_remove_seen,
	require_all_seen
}; chain_sync_config*/

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


}
