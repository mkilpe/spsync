#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/record_storage.hpp>
#include <spsync/core/records/user_change_record.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/octet_vector.hpp>

namespace securepath::sync::util {

std::string const db_name = "record_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

struct test_record_creator {

	auth_record<user_change_record> test_user_change() {
		record_tag tag = test::random_octet_vector(16);
		auth_record<user_change_record> test_record{
			user_change_record{record_base{
				chain_block_id{last_server_seq++, last_chain_hash}, octet_vector{}, sequence_number{1}},
				plain_user_change_data{},
				encrypted_record_header<user_change_header>{}}, content_auth{tag}};
		chain_block block{test_record};
		block.set_server_sequence_and_parent_hash(last_server_seq, last_chain_hash);
		last_chain_hash = block.hash();
		last_tag = tag;
		return test_record;
	}

	sequence_number last_server_seq{};
	record_tag last_tag{};
	octet_vector last_chain_hash{};
};

TEST_CASE("record_storage", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);

	CHECK(storage.last_block().sequence == sequence_number{});
	CHECK(!storage.find_last());
	CHECK(!storage.find_last(object_id{}));
	CHECK(!storage.find_first(object_id{}));
	CHECK(!storage.find(record_tag{}));

	test_record_creator creator;
	auto root_handle = storage.create(creator.test_user_change());
	REQUIRE(root_handle);

	// state needs to be in_sync for these to be found
	CHECK(storage.last_block().sequence == sequence_number{});
	CHECK(!storage.find_last());
	CHECK(!storage.find_last(object_id{}));
	CHECK(!storage.find_first(object_id{}));
	CHECK(!storage.find(record_tag{}));

	{
		CHECK(root_handle->state() == record_state::unknown);
		CHECK(root_handle->parent_block_hash().empty());
		CHECK(root_handle->block_id().sequence == sequence_number{});
		CHECK(root_handle->record().sequence() == sequence_number{});
	}

	{ //set state and server sequence
		root_handle->set_in_sync(chain_block_id{creator.last_server_seq, creator.last_chain_hash}, octet_vector{});
		CHECK(storage.last_block().sequence == creator.last_server_seq);
		CHECK(root_handle->block_id().sequence == creator.last_server_seq);
		CHECK(root_handle->state() == record_state::in_sync);
	}

	{ // check find_last returns correct data
		auto h = storage.find_last();
		REQUIRE(h);
		CHECK(h->tag() == creator.last_tag);
		CHECK(h->parent_block_hash().empty());
		CHECK(h->block_id().sequence == sequence_number{1});
		CHECK(h->state() == record_state::in_sync);
	}
	{ // check find returns correct data
		auto h = storage.find_tag(creator.last_tag);
		REQUIRE(h);
		CHECK(h->tag() == creator.last_tag);
		CHECK(h->parent_block_hash().empty());
		CHECK(h->block_id().sequence == sequence_number{1});
		CHECK(h->state() == record_state::in_sync);
	}
	{ // check that creating new record has correct data
		octet_vector parent_block_hash = creator.last_chain_hash;
		CHECK(storage.create(creator.test_user_change()));
		auto h = storage.find_tag(creator.last_tag);
		REQUIRE(h);
		CHECK(h->tag() == creator.last_tag);
		CHECK(h->parent_block_hash().empty());
		CHECK(h->block_id().sequence == sequence_number{});
		CHECK(h->state() == record_state::unknown);
		CHECK(!h->record().tag().empty());

		h->set_in_sync(chain_block_id{creator.last_server_seq, creator.last_chain_hash}, parent_block_hash);
		h = storage.find_last();
		CHECK(h->tag() == creator.last_tag);
		CHECK(storage.last_block().sequence == creator.last_server_seq);
		CHECK(h->parent_block_hash() == parent_block_hash);
	}
	{ // change state to invalid
		auto h = storage.find_last();
		REQUIRE(h);
		CHECK(h->state() == record_state::in_sync);
		h->set_state(record_state::invalid);
		CHECK(h->state() == record_state::invalid);

		CHECK(storage.find_last() != h);
		auto ih = storage.find_tag(h->tag());
		REQUIRE(ih);
		CHECK(ih->state() == record_state::invalid);
	}
}


TEST_CASE("record_storage root", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	sequence_number seq{0};
	octet_vector parent_block_hash;
	test_record_creator creator;
	for(int i = 0; i != 10; ++i) {
		auto h = storage.create(creator.test_user_change());
		REQUIRE(h);
		h->set_in_sync(chain_block_id{creator.last_server_seq, creator.last_chain_hash}, parent_block_hash);
		CHECK(h->block_id().sequence == ++seq);
		parent_block_hash = creator.last_chain_hash;
	}
	auto root = storage.find_root();
	REQUIRE(root);
	CHECK(root->block_id().sequence == sequence_number{1});
	CHECK(root->parent_block_hash().empty());
}

//test only unique sequences/block hashes work
TEST_CASE("record_storage unique seq", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_record_creator creator;

	auto h1 = storage.create(creator.test_user_change());
	h1->set_in_sync(chain_block_id{creator.last_server_seq, creator.last_chain_hash}, octet_vector{});

	auto h2 = storage.create(creator.test_user_change());
	// use same block id
	CHECK_THROWS(h2->set_in_sync(h1->block_id(), octet_vector{}));
	h2->set_in_sync(chain_block_id{creator.last_server_seq, creator.last_chain_hash}, h1->block_id().hash);

	auto h3 = storage.create(creator.test_user_change());
	// use same parent block hash
	CHECK_THROWS(h3->set_in_sync(chain_block_id{creator.last_server_seq, creator.last_chain_hash}, h1->block_id().hash));
	// use same sequence number
	CHECK_THROWS(h3->set_in_sync(chain_block_id{1, creator.last_chain_hash}, h2->block_id().hash));
	// use same block hash
	CHECK_THROWS(h3->set_in_sync(chain_block_id{creator.last_server_seq, h1->block_id().hash}, h2->block_id().hash));
}

// test only unique tags work
TEST_CASE("record_storage unique tag", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_record_creator creator;

	auto block = creator.test_user_change();
	auto h = storage.create(block);
	REQUIRE(h);
	CHECK_THROWS(storage.create(block));
}

}
