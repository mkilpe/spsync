#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <spsync/core/records/chain_block.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/server/server_lib/chain_sync.hpp>

namespace securepath::sync {

std::string const db_name = "record_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

struct test_record_creator {

	chain_block test_user_change() {
		record_tag tag = test::random_octet_vector(16);
		auth_record<user_change_record> test_record{
			user_change_record{record_base{
				chain_block_id{last_server_seq++, last_chain_hash}, octet_vector{}, sequence_number{1}},
				plain_user_change_data{},
				encrypted_record_header<user_change_header>{}}, util::content_auth{tag}};
		chain_block block{test_record};
		block.set_server_sequence_and_parent_hash(last_server_seq, last_chain_hash);
		last_chain_hash = block.hash();
		last_tag = tag;
		return block;
	}
	/*
	chain_block test_data_change() {

	}

	chain_block test_segment() {

	}
	*/
	sequence_number last_server_seq{};
	record_tag last_tag{};
	octet_vector last_chain_hash{};
};

/*
enum class sync_mode {
	allow_all,
	require_special_seen,
	require_data_add_remove_seen,
	require_all_seen
}; chain_sync_config*/

// util::result<chain_block> commit_block(chain_block const&);

TEST_CASE("chain_sync default config", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name));

	test_record_creator creator;
	auto rec = creator.test_user_change();
	CHECK(sync.commit_block(rec));
	CHECK(check_result_error(sync.commit_block(rec), protocol::errc::record_already_committed));
}

}
