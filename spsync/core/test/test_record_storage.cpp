#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/record_storage.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/octet_vector.hpp>

#include <spsync/test/test_block_creator.hpp>

namespace securepath::sync::test {

std::string const db_name = "record_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

using util::content_auth;

TEST_CASE("record_storage", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);

	CHECK(storage.last_block().sequence == sequence_number{});
	CHECK(storage.last_block(true).sequence == sequence_number{});
	CHECK(!storage.find_last());
	CHECK(!storage.find_last(true));
	CHECK(!storage.find_last(object_id{}));
	CHECK(!storage.find_first(object_id{}));
	CHECK(!storage.find(record_tag{}));
	CHECK(!storage.find(sequence_number{}));
	CHECK(!storage.find(sequence_number{1}));
	CHECK(storage.highest_sequence_number() == sequence_number{});

	test_block_creator creator;
	auto root_handle = storage.create(creator.test_user_change().to_auth_record<user_change_record>());
	REQUIRE(root_handle);

	// state needs to be in_sync for these to be found
	CHECK(storage.last_block().sequence == sequence_number{});
	CHECK(storage.last_block(true).sequence == creator.last_server_seq);
	CHECK(!storage.find_last());
	CHECK(storage.find_last(true) == root_handle);
	CHECK(!storage.find_last(object_id{}));
	CHECK(!storage.find_first(object_id{}));
	CHECK(!storage.find(record_tag{}));

	{
		CHECK(root_handle->type() == user_change_record_tag);
		CHECK(root_handle->state() == record_state::pending_commit);
		CHECK(root_handle->parent_block_hash().empty());
		CHECK(root_handle->block_id().sequence == sequence_number{1});
		CHECK(root_handle->record().sequence() == sequence_number{1});
	}

	{ //set state and server sequence
		root_handle->set_state(record_state::in_sync, chain_block_id{creator.last_server_seq, creator.last_chain_hash}, octet_vector{});
		CHECK(storage.last_block().sequence == creator.last_server_seq);
		CHECK(storage.last_block(true).sequence == creator.last_server_seq);
		CHECK(root_handle->block_id().sequence == creator.last_server_seq);
		CHECK(root_handle->state() == record_state::in_sync);
	}

	{ // check find_last returns correct data
		auto h = storage.find_last();
		REQUIRE(h);
		CHECK(storage.find_last(true) == h);
		CHECK(h->tag() == creator.last_tag);
		CHECK(h->parent_block_hash().empty());
		CHECK(h->block_id().sequence == sequence_number{1});
		CHECK(storage.highest_sequence_number() == sequence_number{1});
		CHECK(h->state() == record_state::in_sync);
	}
	{
		auto h = storage.find(sequence_number{1});
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
		CHECK(storage.create(creator.test_user_change().to_auth_record<user_change_record>()));
		auto h = storage.find_tag(creator.last_tag);
		REQUIRE(h);
		CHECK(h->tag() == creator.last_tag);
		CHECK(h->parent_block_hash().empty());
		CHECK(h->block_id().sequence == sequence_number{2});
		CHECK(h->type() == user_change_record_tag);
		CHECK(h->state() == record_state::pending_commit);
		CHECK(!h->record().tag().empty());

		h->set_state(record_state::in_sync, chain_block_id{creator.last_server_seq, creator.last_chain_hash}, parent_block_hash);
		h = storage.find_last();
		CHECK(h->tag() == creator.last_tag);
		CHECK(storage.last_block().sequence == creator.last_server_seq);
		CHECK(h->parent_block_hash() == parent_block_hash);
	}
	{ // check find sequence number
		auto h = storage.find(creator.last_server_seq);
		CHECK(h->tag() == creator.last_tag);
	}
	{ // change state to invalid
		auto h = storage.find_last();
		REQUIRE(h);
		CHECK(h->state() == record_state::in_sync);
		h->set_state(record_state::invalid);
		CHECK(h->state() == record_state::invalid);
		CHECK(!storage.find(creator.last_server_seq));
		CHECK(storage.highest_sequence_number() == sequence_number{1});

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
	test_block_creator creator;
	for(int i = 0; i != 10; ++i) {
		auto h = storage.create(creator.test_user_change().to_auth_record<user_change_record>());
		REQUIRE(h);
		h->set_state(record_state::in_sync, chain_block_id{creator.last_server_seq, creator.last_chain_hash}, parent_block_hash);
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
	test_block_creator creator;

	auto h1 = storage.create(creator.test_user_change().to_auth_record<user_change_record>());
	h1->set_state(record_state::in_sync, chain_block_id{creator.last_server_seq, creator.last_chain_hash}, octet_vector{});

	auto h2 = storage.create(creator.test_user_change().to_auth_record<user_change_record>());
	// use same block id
	CHECK_THROWS(h2->set_state(record_state::in_sync, h1->block_id(), octet_vector{}));
	h2->set_state(record_state::in_sync, chain_block_id{creator.last_server_seq, creator.last_chain_hash}, h1->block_id().hash);

	auto h3 = storage.create(creator.test_user_change().to_auth_record<user_change_record>());

	// use same sequence number
	CHECK_THROWS(h3->set_state(record_state::in_sync, chain_block_id{1, creator.last_chain_hash}, h2->block_id().hash));
	// use same block hash
	CHECK_THROWS(h3->set_state(record_state::in_sync, chain_block_id{creator.last_server_seq, h1->block_id().hash}, h2->block_id().hash));
	// same seq with other than in_sync state still works
	CHECK_NOTHROW(h3->set_state(record_state::pending_commit, chain_block_id{1, creator.last_chain_hash}, h2->block_id().hash));
}

// test only unique tags work
TEST_CASE("record_storage unique tag", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;

	auto block = creator.test_user_change().to_auth_record<user_change_record>();
	auto h = storage.create(block);
	REQUIRE(h);
	CHECK_THROWS(storage.create(block));
}


TEST_CASE("record_storage data change not synced", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;

	// first record needs to be user_change
	storage.create(creator.test_user_change(), record_state::in_sync);

	// test that blocks which are not in_sync state are not found with find_first/find_last
	auto block = creator.test_data_change();
	auto h = storage.create(block, record_state::unknown);
	REQUIRE(h);
	for(auto&& r : block.deserialise_to<data_change_record>()) {
		CHECK(!storage.find_first(r.data.id));
		CHECK(!storage.find_last(r.data.id));
	}
	h->set_state(record_state::in_sync);
	for(auto&& r : block.deserialise_to<data_change_record>()) {
		CHECK(storage.find_first(r.data.id));
		CHECK(storage.find_last(r.data.id));
	}
}

inline bool check_tag(record_handle h, octet_vector tag) {
	return h && h->tag() == tag;
}

TEST_CASE("record_storage data change", "[unit]") {
	auto oids = GENERATE(1, 3, 10, 103);

	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;

	// first record needs to be user_change
	storage.create(creator.test_user_change(), record_state::in_sync);

	chain_block first_change_block;
	{
		first_change_block = creator.test_multi_data_change(oids);
		auto h = storage.create(first_change_block, record_state::in_sync);
		REQUIRE(h);
		CHECK(h->type() == data_change_record_tag);
		for(auto&& r : first_change_block.deserialise_to<data_change_record>()) {
			CHECK(check_tag(storage.find_first(r.data.id), h->tag()));
			CHECK(check_tag(storage.find_last(r.data.id), h->tag()));
		}
	}

	{
		auto block = creator.test_multi_data_change(oids);
		auto h = storage.create(block, record_state::in_sync);
		REQUIRE(h);
		for(auto&& r : block.deserialise_to<data_change_record>()) {
			CHECK(check_tag(storage.find_first(r.data.id), h->tag()));
			CHECK(check_tag(storage.find_last(r.data.id), h->tag()));
		}

		// check the first one is still as should
		for(auto&& r : first_change_block.deserialise_to<data_change_record>()) {
			CHECK(check_tag(storage.find_first(r.data.id), first_change_block.tag()));
			CHECK(check_tag(storage.find_last(r.data.id), first_change_block.tag()));
		}
	}
	// create follow up
	{
		auto block = creator.test_followup_data_change(first_change_block);
		auto h = storage.create(block, record_state::in_sync);
		REQUIRE(h);
		for(auto&& r : block.deserialise_to<data_change_record>()) {
			CHECK(check_tag(storage.find_first(r.data.id), first_change_block.tag()));
			CHECK(check_tag(storage.find_last(r.data.id), h->tag()));
		}
	}
}


TEST_CASE("record_storage long_chain data change", "[unit]") {
	auto length = GENERATE(3, 13, 203);

	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;

	// first record needs to be user_change
	storage.create(creator.test_user_change(), record_state::in_sync);

	std::vector<chain_block> blocks;
	{
		blocks.push_back(creator.test_data_change());
		storage.create(blocks.back(), record_state::in_sync);
	}
	for(int i = 0; i != length; ++i) {
		blocks.push_back(creator.test_followup_data_change(blocks.back()));
		storage.create(blocks.back(), record_state::in_sync);
	}

	object_id oid = blocks.front().deserialise_to<data_change_record>().begin()->data.id;

	CHECK(check_tag(storage.find_first(oid), blocks.front().tag()));
	CHECK(check_tag(storage.find_last(oid), blocks.back().tag()));

	/*auto handle = storage.find_last(oid);
	int count = 0;
	while(handle && !blocks.empty()) {
		++count;
		CHECK(check_tag(handle, blocks.back().tag()));
		handle = ...
		blocks.pop_back();
	}
	CHECK(count == length+1);*/
}


TEST_CASE("record_storage pending commits", "[unit]") {
	//find_first_pending_commit
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;

	// first record needs to be user_change
	storage.create(creator.test_user_change(), record_state::in_sync);
	auto const initial_hash = creator.last_chain_hash;

	auto const initial_seq = creator.last_server_seq;

	CHECK(!storage.find_first_pending_commit());
	CHECK(storage.last_block().sequence == initial_seq);
	CHECK(storage.last_block(true).sequence == initial_seq);

	auto first_pending = storage.create(creator.test_data_change(), record_state::pending_commit);
	auto const tag_of_first_pending = first_pending->tag();

	//see we find the pending commit
	CHECK(storage.find_first_pending_commit());
	CHECK(storage.find_first_pending_commit()->tag() == tag_of_first_pending);
	CHECK(storage.last_block().sequence == initial_seq);
	CHECK(storage.last_block(true).sequence == creator.last_server_seq);

	storage.create(creator.test_data_change(), record_state::pending_commit);
	auto const tag_of_second_pending = creator.last_tag;

	//still get the first pending
	auto fpending = storage.find_first_pending_commit();
	REQUIRE(fpending);
	CHECK(fpending->tag() == tag_of_first_pending);
	CHECK(storage.last_block().sequence == initial_seq);
	CHECK(storage.last_block(true).sequence == creator.last_server_seq);

	auto second_pending = storage.find_next_pending_commit(fpending);
	REQUIRE(second_pending);
	CHECK(second_pending->tag() == tag_of_second_pending);

	auto record = creator.test_data_change();
	record.set_sequence_and_parent_hash(sequence_number{2}, initial_hash);
	CHECK_NOTHROW(storage.create(record, record_state::in_sync));

	//still get the first pending
	CHECK(storage.find_first_pending_commit());
	CHECK(storage.find_first_pending_commit()->tag() == tag_of_first_pending);

	CHECK_NOTHROW(first_pending->set_state(record_state::in_sync, chain_block_id{3, first_pending->block_id().hash}, creator.last_chain_hash));

	//get the second pending
	CHECK(storage.find_first_pending_commit());
	CHECK(storage.find_first_pending_commit()->tag() == tag_of_second_pending);
}


TEST_CASE("record_storage set record", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;

	// first record needs to be user_change
	storage.create(creator.test_user_change(), record_state::in_sync);
	auto creator_copy = creator;
	auto pending = storage.create(creator_copy.test_data_change(), record_state::pending_commit);
	auto last_seen = storage.create(creator.test_data_change(), record_state::in_sync);

	auto rec = pending->record().deserialise_to<data_change_record>();
	rec.set_last_seen_block(last_seen->block_id());
	chain_block block{rec, content_auth{securepath::test::random_octet_vector(16)}};
	block.set_sequence_and_parent_hash(last_seen->block_id().sequence + 1, last_seen->block_id().hash);
	CHECK_NOTHROW(pending->set_record(block));

	// in_sync state record cannot be changed
	CHECK_THROWS(last_seen->set_record(block));
}


TEST_CASE("record_storage pending commits with same seq", "[unit]") {
	//find_first_pending_commit
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;

	// first record needs to be user_change
	storage.create(creator.test_user_change(), record_state::in_sync);

	auto tmp_c = creator;
	storage.create(tmp_c.test_data_change(), record_state::in_sync);
	auto const initial_hash = tmp_c.last_chain_hash;
	auto const initial_seq = tmp_c.last_server_seq;

	chain_block_id first_p;
	chain_block_id last_p;
	// create three records with same sequence and parent

	{
		auto tmp_c = creator;
		auto h = storage.create(tmp_c.test_data_change(), record_state::pending_commit);
		first_p = h->block_id();
	}
	{
		auto tmp_c = creator;
		storage.create(tmp_c.test_data_change(), record_state::pending_commit);
	}
	{
		auto tmp_c = creator;
		auto h = storage.create(tmp_c.test_data_change(), record_state::pending_commit);
		last_p = h->block_id();
	}

	//see we find the pending commit
	CHECK(storage.last_block().sequence == initial_seq);
	auto l = storage.find_last();
	REQUIRE(l);
	CHECK(l->block_id() == storage.last_block());
	CHECK(l->block_id().hash == initial_hash);

	CHECK(storage.find_first_pending_commit()->block_id() == first_p);
	CHECK(storage.last_block(true) == last_p);
	CHECK(storage.find_last(true)->block_id() == last_p);
}


TEST_CASE("record_storage acked state", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	record_storage storage(db_conn);

	test_block_creator creator;
	auto block = creator.test_user_change();
	auto h = storage.create(block, record_state::acked);
	REQUIRE(h);
	CHECK(h->state() == record_state::acked);
	CHECK(is_valid_state(record_state::acked));

	// acked records are found by their state and carry the server assigned sequence
	CHECK(storage.find(block.sequence(), record_state::acked) == h);
	CHECK(!storage.find(block.sequence()));

	// acked shares the unique sequence selector with in_sync: no second record may
	// claim the same sequence in either state
	auto conflicting = creator.test_user_change();
	conflicting.set_sequence_and_parent_hash(block.sequence(), octet_vector{});
	CHECK_THROWS(storage.create(conflicting, record_state::acked));
	CHECK_THROWS(storage.create(conflicting, record_state::in_sync));

	// the single server transition: acked -> in_sync in the same step
	h->set_state(record_state::in_sync);
	CHECK(h->state() == record_state::in_sync);
	CHECK(storage.find(block.sequence()) == h);
}

}
