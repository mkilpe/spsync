// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/record_storage.hpp>
#include <spsync/core/data/data_state_table.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/octet_vector.hpp>

#include <spsync/test/test_block_creator.hpp>

#include <algorithm>
#include <optional>
#include <vector>

namespace securepath::sync::test {

std::string const db_name = "record_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

using util::content_auth;

namespace {

/// a new database for a test
database::connection_ptr fresh_test_db() {
	remove_database_test_db();
	return database::sqlite::create_sqlite_connection(db_name);
}

/// a storage with its root record in sync, the creator holding the chain state
struct storage_with_root {
	storage_with_root() {
		// first record needs to be user_change
		storage.create(creator.test_user_change(), record_state::in_sync);
	}

public:
	database::connection_ptr db_conn{fresh_test_db()};
	record_storage storage{db_conn};
	test_block_creator creator;
};

/// an empty storage finds nothing
void check_empty_storage(record_storage& storage) {
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
}

/// the root record just created: pending, found only when pending records count
void check_pending_root(record_storage& storage, record_handle const& root_handle, test_block_creator const& creator) {
	// state needs to be in_sync for these to be found
	CHECK(storage.last_block().sequence == sequence_number{});
	CHECK(storage.last_block(true).sequence == creator.last_server_seq);
	CHECK(!storage.find_last());
	CHECK(storage.find_last(true) == root_handle);
	CHECK(!storage.find_last(object_id{}));
	CHECK(!storage.find_first(object_id{}));
	CHECK(!storage.find(record_tag{}));

	CHECK(root_handle->type() == user_change_record_tag);
	CHECK(root_handle->state() == record_state::pending_commit);
	CHECK(root_handle->parent_block_hash().empty());
	CHECK(root_handle->block_id().sequence == sequence_number{1});
	CHECK(root_handle->record().sequence() == sequence_number{1});
}

/// a handle of the root record in sync, however it was found
void check_root_handle(record_handle const& h, test_block_creator const& creator) {
	REQUIRE(h);
	CHECK(h->tag() == creator.last_tag);
	CHECK(h->parent_block_hash().empty());
	CHECK(h->block_id().sequence == sequence_number{1});
	CHECK(h->state() == record_state::in_sync);
}

/// the root set in sync: found as the last record, by sequence and by tag
void check_root_in_sync(record_storage& storage, record_handle const& root_handle, test_block_creator const& creator) {
	//set state and server sequence
	root_handle->set_state(record_state::in_sync, chain_block_id{creator.last_server_seq, creator.last_chain_hash}, octet_vector{});
	CHECK(storage.last_block().sequence == creator.last_server_seq);
	CHECK(storage.last_block(true).sequence == creator.last_server_seq);
	CHECK(root_handle->block_id().sequence == creator.last_server_seq);
	CHECK(root_handle->state() == record_state::in_sync);

	// check find_last returns correct data
	auto h = storage.find_last();
	check_root_handle(h, creator);
	CHECK(storage.find_last(true) == h);
	CHECK(storage.highest_sequence_number() == sequence_number{1});
	check_root_handle(storage.find(sequence_number{1}), creator);
	// check find returns correct data
	check_root_handle(storage.find_tag(creator.last_tag), creator);
}

/// a second record created pending, then set in sync with its parent hash
void check_second_record(record_storage& storage, test_block_creator& creator) {
	// check that creating new record has correct data
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

	// check find sequence number
	CHECK(storage.find(creator.last_server_seq)->tag() == creator.last_tag);
}

/// the last record set invalid: off the chain, still found by its tag
void check_invalidate_last(record_storage& storage, test_block_creator const& creator) {
	// change state to invalid
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

/// the tag of the first pending commit, none when there is none
std::optional<record_tag> first_pending_tag(record_storage& storage) {
	auto h = storage.find_first_pending_commit();
	return h ? std::optional<record_tag>{h->tag()} : std::nullopt;
}

/// five records in sync: a user change, an object, its follow-up, another object, a user change
std::vector<chain_block> create_five_in_sync(record_storage& storage, test_block_creator& creator) {
	std::vector<chain_block> blocks;
	blocks.push_back(creator.test_user_change());
	blocks.push_back(creator.test_data_change());
	blocks.push_back(creator.test_followup_data_change(blocks.back()));
	blocks.push_back(creator.test_data_change());
	blocks.push_back(creator.test_user_change());
	for(auto const& b : blocks) {
		REQUIRE(storage.create(b, record_state::in_sync));
	}
	return blocks;
}

/// the object chains below a cut and the ranges of the five record chain
void check_chains_below_cut(record_storage& storage, std::vector<chain_block> const& blocks) {
	auto contains = [](auto const& tags, record_tag const& t) {
		return std::ranges::find(tags, t) != tags.end();
	};
	{ // the object chains below the cut: first object {b3, b2}, second {b4}
		auto tags = storage.object_chain_tags_below(sequence_number{5});
		CHECK(tags.size() == 3);
		CHECK(contains(tags, blocks[1].tag()));
		CHECK(contains(tags, blocks[2].tag()));
		CHECK(contains(tags, blocks[3].tag()));
		CHECK(!contains(tags, blocks[0].tag()));
	}
	{ // a record at or past the cut is not part of the retained set
		auto tags = storage.object_chain_tags_below(sequence_number{4});
		CHECK(tags.size() == 2);
		CHECK(!contains(tags, blocks[3].tag()));
	}
	{ // find_range respects the range and the cap
		CHECK(storage.find_range(sequence_number{1}, sequence_number{5}).size() == 5);
		CHECK(storage.find_range(sequence_number{1}, sequence_number{5}, record_state::in_sync, 2).size() == 2);
		CHECK(storage.find_range(sequence_number{6}, sequence_number{9}).empty());
	}
}

}

TEST_CASE("record_storage", "[unit]") {
	auto db_conn = fresh_test_db();
	record_storage storage(db_conn);
	check_empty_storage(storage);

	test_block_creator creator;
	auto root_handle = storage.create(creator.test_user_change().to_auth_record<user_change_record>());
	REQUIRE(root_handle);
	check_pending_root(storage, root_handle, creator);
	check_root_in_sync(storage, root_handle, creator);
	check_second_record(storage, creator);
	check_invalidate_last(storage, creator);
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
	storage_with_root s;
	auto& storage = s.storage;
	auto& creator = s.creator;
	auto const initial_hash = creator.last_chain_hash;
	auto const initial_seq = creator.last_server_seq;

	CHECK(!storage.find_first_pending_commit());
	CHECK(storage.last_block().sequence == initial_seq);
	CHECK(storage.last_block(true).sequence == initial_seq);

	auto first_pending = storage.create(creator.test_data_change(), record_state::pending_commit);
	auto const tag_of_first_pending = first_pending->tag();

	//see we find the pending commit
	CHECK(first_pending_tag(storage) == tag_of_first_pending);
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
	CHECK(first_pending_tag(storage) == tag_of_first_pending);

	CHECK_NOTHROW(first_pending->set_state(record_state::in_sync, chain_block_id{3, first_pending->block_id().hash}, creator.last_chain_hash));

	//get the second pending
	CHECK(first_pending_tag(storage) == tag_of_second_pending);
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

	auto const rec_tag_before = pending->tag();
	auto rec = pending->record().deserialise_to<data_change_record>();
	rec.set_last_seen_block(last_seen->block_id());
	chain_block block{rec, content_auth{securepath::test::random_octet_vector(16)}};
	block.set_sequence_and_parent_hash(last_seen->block_id().sequence + 1, last_seen->block_id().hash);
	CHECK_NOTHROW(pending->set_record(block));
	{
		// the object rows moved to the new tag; none are left under the old one
		auto q = db_conn->prepare("SELECT count(*) FROM record_objects WHERE tag = :t;");
		q.bind(":t", rec_tag_before);
		CHECK(q.execute().value<std::int64_t>(0).value_or(-1) == 0);
		auto n = db_conn->prepare("SELECT count(*) FROM record_objects WHERE tag = :t;");
		n.bind(":t", block.tag());
		CHECK(n.execute().value<std::int64_t>(0).value_or(-1) == 1);
	}

	// in_sync state record cannot be changed
	CHECK_THROWS(last_seen->set_record(block));
}

// a demoted record loses the sequence assignment of the sequence it no longer holds
TEST_CASE("record_storage demote clears the assignment", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;
	storage.create(creator.test_user_change(), record_state::in_sync);
	auto acked = storage.create(creator.test_data_change(), record_state::acked);
	acked->set_assignment(octet_vector(8, 1), octet_vector(32, 2), acked->block_id().sequence);
	REQUIRE(!acked->assignment().empty());

	auto removed = storage.truncate_from(acked->block_id().sequence, true);
	CHECK(removed.empty());
	CHECK(acked->state() == record_state::pending_commit);
	CHECK(acked->assignment().empty());
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


TEST_CASE("record_storage truncate_from", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	record_storage storage(db_conn);

	test_block_creator creator;
	REQUIRE(storage.create(creator.test_user_change(), record_state::in_sync));
	auto b2 = creator.test_data_change();
	REQUIRE(storage.create(b2, record_state::in_sync));
	auto b3 = creator.test_data_change();
	REQUIRE(storage.create(b3, record_state::acked));
	auto b4 = creator.test_data_change();
	REQUIRE(storage.create(b4, record_state::pending_sync));
	auto local = creator.test_data_change();
	REQUIRE(storage.create(local.to_auth_record<data_change_record>()));

	object_id const oid2 = b2.deserialise_to<data_change_record>().begin()->data.id;
	CHECK(storage.find_last(oid2));

	auto held = storage.find(sequence_number{2});
	REQUIRE(held);

	CHECK_THROWS(storage.truncate_from(sequence_number{}));

	auto removed = storage.truncate_from(sequence_number{2});
	REQUIRE(removed.size() == 3);
	CHECK(removed[0].tag() == b2.tag());
	CHECK(removed[1].tag() == b3.tag());
	CHECK(removed[2].tag() == b4.tag());

	// rows and their object records are gone, the root stays
	CHECK(storage.last_block().sequence == sequence_number{1});
	CHECK(!storage.find(sequence_number{2}));
	CHECK(!storage.find(sequence_number{3}, record_state::acked));
	CHECK(!storage.find(sequence_number{4}, record_state::pending_sync));
	CHECK(!storage.find_last(oid2));
	CHECK(held->state() == record_state::invalid);

	// pending_commit records are never touched
	auto pending = storage.find_first_pending_commit();
	REQUIRE(pending);
	CHECK(pending->tag() == local.tag());

	// the freed sequences can be committed again (unique sequence selector is released)
	auto again = creator.test_data_change();
	again.set_sequence_and_parent_hash(sequence_number{2}, storage.last_block().hash);
	CHECK(storage.create(again, record_state::in_sync));
	CHECK(storage.last_block().sequence == sequence_number{2});
}

TEST_CASE("record_storage truncate_from demotes acked", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	record_storage storage(db_conn);

	test_block_creator creator;
	REQUIRE(storage.create(creator.test_user_change(), record_state::in_sync));
	auto b2 = creator.test_data_change();
	REQUIRE(storage.create(b2, record_state::in_sync));
	auto b3 = creator.test_data_change();
	auto acked_handle = storage.create(b3, record_state::acked);
	REQUIRE(acked_handle);

	auto removed = storage.truncate_from(sequence_number{2}, true);
	REQUIRE(removed.size() == 1);
	CHECK(removed[0].tag() == b2.tag());

	// the acked record is demoted to pending_commit, keeping op id and content for rebase
	CHECK(acked_handle->state() == record_state::pending_commit);
	auto pending = storage.find_first_pending_commit();
	REQUIRE(pending);
	CHECK(pending == acked_handle);
	CHECK(storage.find_op_id(b3.deserialise_to<data_change_record>().op_id()) == acked_handle);
	CHECK(pending->record().check_matches_without_server_data(b3));

	// demotion releases the unique sequence selector: the sequence can be assigned again
	auto again = creator.test_user_change();
	again.set_sequence_and_parent_hash(b3.sequence(), octet_vector{});
	CHECK(storage.create(again, record_state::in_sync));
}

TEST_CASE("record_storage truncate_prefix and object chains", "[unit]") {
	auto db_conn = fresh_test_db();
	record_storage storage(db_conn);

	test_block_creator creator;
	auto const blocks = create_five_in_sync(storage, creator);
	auto const& b1 = blocks[0];
	auto const& b2 = blocks[1];
	auto const& b3 = blocks[2];
	auto const& b4 = blocks[3];
	check_chains_below_cut(storage, blocks);

	auto held = storage.find(sequence_number{1});
	REQUIRE(held);
	auto removed = storage.truncate_prefix(sequence_number{5}, {b2.tag(), b3.tag(), b4.tag()});
	REQUIRE(removed.size() == 1);
	CHECK(removed[0].tag() == b1.tag());

	// the retained records and everything at or past the cut stay, the rest is gone
	CHECK(held->state() == record_state::invalid);
	CHECK(!storage.find(sequence_number{1}));
	CHECK(storage.find(sequence_number{2}));
	CHECK(storage.find(sequence_number{5}));
	CHECK(storage.last_block().sequence == sequence_number{5});
	CHECK(storage.find_range(sequence_number{1}, sequence_number{5}).size() == 4);

	// object lookups still work on the retained chain
	object_id const oid = b2.deserialise_to<data_change_record>().begin()->data.id;
	REQUIRE(storage.find_last(oid));
	CHECK(storage.find_last(oid)->tag() == b3.tag());

	CHECK_THROWS(storage.truncate_prefix(sequence_number{}, {}));
}

TEST_CASE("record_storage segment queries", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	record_storage storage(db_conn);

	test_block_creator creator;
	CHECK(!storage.find_last_of_type(segment_record_tag));
	CHECK(storage.tags_in_range(sequence_number{1}, sequence_number{10}).empty());

	auto b1 = creator.test_user_change();
	REQUIRE(storage.create(b1, record_state::in_sync));
	auto b2 = creator.test_data_change();
	REQUIRE(storage.create(b2, record_state::in_sync));
	auto s1 = creator.test_segment(plain_segment_data{sequence_number{1}, sequence_number{3}
		, {b1.tag(), b2.tag()}});
	REQUIRE(storage.create(s1, record_state::in_sync));

	{ // the newest record per type is found
		auto h = storage.find_last_of_type(segment_record_tag);
		REQUIRE(h);
		CHECK(h->tag() == s1.tag());
		CHECK(h->type() == segment_record_tag);
		CHECK(storage.find_last_of_type(user_change_record_tag)->tag() == b1.tag());
		CHECK(storage.find_last_of_type(data_change_record_tag)->tag() == b2.tag());
	}
	{ // range tags come back in sequence order
		auto tags = storage.tags_in_range(sequence_number{1}, sequence_number{2});
		REQUIRE(tags.size() == 2);
		CHECK(tags[0] == b1.tag());
		CHECK(tags[1] == b2.tag());
		CHECK(storage.tags_in_range(sequence_number{1}, sequence_number{10}).size() == 3);
		CHECK(storage.tags_in_range(sequence_number{4}, sequence_number{10}).empty());
	}
	{ // records without a server sequence are not part of a range
		auto pending = creator.test_data_change();
		REQUIRE(storage.create(pending, record_state::pending_commit));
		CHECK(storage.tags_in_range(sequence_number{1}, sequence_number{10}).size() == 3);
	}
	{ // a newer segment becomes the newest of its type
		auto s2 = creator.test_segment(plain_segment_data{sequence_number{3}, sequence_number{5}
			, {s1.tag(), creator.created_tags[3]}, s1.tag()});
		REQUIRE(storage.create(s2, record_state::in_sync));
		auto h = storage.find_last_of_type(segment_record_tag);
		REQUIRE(h);
		CHECK(h->tag() == s2.tag());
		auto seg = h->record().deserialise_to<segment_record>();
		CHECK(seg.data().previous_segment_tag() == s1.tag());
	}
}

TEST_CASE("record_storage assignment round-trip", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	record_storage storage(db_conn);

	test_block_creator creator;
	auto h = storage.create(creator.test_user_change(), record_state::in_sync);
	REQUIRE(h);
	CHECK(h->assignment().empty());

	octet_vector env = securepath::test::random_octet_vector(64);
	h->set_assignment(env);
	CHECK(h->assignment() == env);
	CHECK(storage.find_tag(h->tag())->assignment() == env);
}


// the fetch cursor of the engine: the first gap in the received sequences (plan 4.5)
TEST_CASE("record_storage first missing sequence", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;

	CHECK(!storage.first_missing_sequence().is_valid());

	storage.create(creator.test_user_change(), record_state::in_sync);
	storage.create(creator.test_data_change(), record_state::in_sync);
	CHECK(storage.highest_sequence_number() == sequence_number{2});
	CHECK(!storage.first_missing_sequence().is_valid());

	// 5 and 6 arrive ahead of 3 and 4 (a weak mode accepts them, an interrupted fetch leaves them)
	auto r5 = creator.test_data_change();
	r5.set_sequence_and_parent_hash(sequence_number{5}, octet_vector{});
	storage.create(r5, record_state::pending_sync);
	auto r6 = creator.test_data_change();
	r6.set_sequence_and_parent_hash(sequence_number{6}, octet_vector{});
	storage.create(r6, record_state::acked);
	// highest_sequence_number() counts in_sync and pending_sync only; the gap search
	// treats an acked record as received too (it carries the server's sequence)
	CHECK(storage.highest_sequence_number() == sequence_number{5});
	CHECK(storage.first_missing_sequence() == sequence_number{3});
	CHECK(storage.first_missing_sequence(sequence_number{2}) == sequence_number{3});
	CHECK(storage.first_missing_sequence(sequence_number{3}) == sequence_number{3});
	CHECK(storage.first_missing_sequence(sequence_number{4}) == sequence_number{4});
	CHECK(!storage.first_missing_sequence(sequence_number{5}).is_valid());
	CHECK(!storage.first_missing_sequence(sequence_number{7}).is_valid());

	// pending commits carry no server sequence and never count
	storage.create(creator.test_data_change(), record_state::pending_commit);
	CHECK(storage.first_missing_sequence() == sequence_number{3});

	auto r3 = creator.test_data_change();
	r3.set_sequence_and_parent_hash(sequence_number{3}, octet_vector{});
	storage.create(r3, record_state::in_sync);
	CHECK(storage.first_missing_sequence() == sequence_number{4});
	auto r4 = creator.test_data_change();
	r4.set_sequence_and_parent_hash(sequence_number{4}, octet_vector{});
	storage.create(r4, record_state::in_sync);
	CHECK(!storage.first_missing_sequence().is_valid());
}

// the very first sequence can be the gap
TEST_CASE("record_storage first missing sequence at start", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);

	record_storage storage(db_conn);
	test_block_creator creator;
	creator.test_user_change();
	auto r2 = creator.test_data_change();
	r2.set_sequence_and_parent_hash(sequence_number{2}, octet_vector{});
	storage.create(r2, record_state::pending_sync);
	CHECK(storage.first_missing_sequence() == sequence_number{1});
	CHECK(!storage.first_missing_sequence(sequence_number{2}).is_valid());
}


// (RDS 8) the storage's validity limits survive a reopen next to the cursor owner
TEST_CASE("record_storage limits persist", "[unit]") {
	remove_database_test_db();
	{
		record_storage storage(database::sqlite::create_sqlite_connection(db_name));
		CHECK(storage.limits() == storage_limits{});
		storage.set_cursor_owner(octet_vector(32, 7));
		storage.set_limits(storage_limits{16 * 1024, 512 * 1024});
		CHECK(storage.limits() == storage_limits{16 * 1024, 512 * 1024});
	}
	record_storage storage(database::sqlite::create_sqlite_connection(db_name));
	CHECK(storage.limits() == storage_limits{16 * 1024, 512 * 1024});
	// neither setter clobbers the other's column
	CHECK(storage.cursor_owner() == octet_vector(32, 7));
	storage.set_cursor_owner(octet_vector(32, 8));
	CHECK(storage.limits() == storage_limits{16 * 1024, 512 * 1024});
}


// (RDS 2) changes with a data descriptor point at the row of their data_id; the rows are
// shared and the references follow the records
TEST_CASE("record_storage data references", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	record_storage storage(db_conn);
	data_state_table table{db_conn};
	test_block_creator creator;

	data_descriptor const data_a{5080, 1000, securepath::test::random_octet_vector(64)};
	data_descriptor const data_b{4112, 4096, securepath::test::random_octet_vector(64)};

	REQUIRE(storage.create(creator.test_user_change(), record_state::in_sync));
	// a change without data references nothing
	REQUIRE(storage.create(creator.test_data_change(), record_state::in_sync));
	CHECK(table.all_ids().empty());

	auto const b3 = creator.test_data_change_with_data(data_a);
	REQUIRE(storage.create(b3, record_state::in_sync));
	auto const row_a = table.find(data_a.manifest_digest);
	REQUIRE(row_a);
	CHECK(row_a->descriptor == data_a);
	CHECK(row_a->state == record_data_state::deferred);
	CHECK(row_a->have.count() == 0);
	CHECK(storage.data_reference_count(row_a->local_id) == 1);

	// a known data keeps its row and state
	table.set_state(row_a->local_id, record_data_state::in_sync);
	REQUIRE(storage.create(creator.test_data_change_with_data(data_a), record_state::in_sync));
	REQUIRE(storage.create(creator.test_data_change_with_data(data_b), record_state::in_sync));
	CHECK(table.all_ids().size() == 2);
	CHECK(table.find(data_a.manifest_digest)->state == record_data_state::in_sync);
	CHECK(storage.data_reference_count(row_a->local_id) == 2);
	auto const row_b = table.find(data_b.manifest_digest);
	REQUIRE(row_b);
	CHECK(storage.data_reference_count(row_b->local_id) == 1);
	CHECK(storage.data_reference_count(row_b->local_id + 100) == 0);

	SECTION("confirmed data in a state") {
		// (RDS 3) the uploads owed: upload_pending data of server confirmed records, in commit order
		CHECK(storage.confirmed_data_in_state(record_data_state::upload_pending).empty());
		CHECK(storage.confirmed_data_in_state(record_data_state::in_sync) == std::vector<data_id>{data_a.manifest_digest});
		CHECK(storage.confirmed_data_in_state(record_data_state::deferred) == std::vector<data_id>{data_b.manifest_digest});

		table.set_state(row_a->local_id, record_data_state::upload_pending);
		table.set_state(row_b->local_id, record_data_state::upload_pending);
		// data_a is named by two records: once, at its first record
		CHECK(storage.confirmed_data_in_state(record_data_state::upload_pending)
			== std::vector<data_id>{data_a.manifest_digest, data_b.manifest_digest});

		// the data of a record the server does not have yet is not owed
		data_descriptor const data_c{4112, 4096, securepath::test::random_octet_vector(64)};
		auto creator_copy = creator;
		auto pending = storage.create(creator_copy.test_data_change_with_data(data_c).to_auth_record<data_change_record>());
		REQUIRE(pending);
		table.set_state(table.find(data_c.manifest_digest)->local_id, record_data_state::upload_pending);
		CHECK(storage.confirmed_data_in_state(record_data_state::upload_pending).size() == 2);

		pending->set_state(record_state::acked, chain_block_id{sequence_number{20}, securepath::test::random_octet_vector(64)}, octet_vector{});
		CHECK(storage.confirmed_data_in_state(record_data_state::upload_pending)
			== std::vector<data_id>{data_a.manifest_digest, data_b.manifest_digest, data_c.manifest_digest});
	}

	SECTION("a rebase keeps the reference") {
		auto creator_copy = creator;
		auto pending = storage.create(creator_copy.test_data_change_with_data(data_b).to_auth_record<data_change_record>());
		REQUIRE(pending);
		CHECK(storage.data_reference_count(row_b->local_id) == 2);

		auto last_seen = storage.create(creator.test_data_change(), record_state::in_sync);
		auto rec = pending->record().deserialise_to<data_change_record>();
		rec.set_last_seen_block(last_seen->block_id());
		chain_block block{rec, content_auth{securepath::test::random_octet_vector(16)}};
		block.set_sequence_and_parent_hash(last_seen->block_id().sequence + 1, last_seen->block_id().hash);
		CHECK_NOTHROW(pending->set_record(block));
		CHECK(storage.data_reference_count(row_b->local_id) == 2);
		CHECK(table.all_ids().size() == 2);
	}

	SECTION("an index that follows its records") {
		// (RDS 9) a record server keeps the rows only: the ones nothing references go
		CHECK(storage.remove_unreferenced_data().empty());
		CHECK(table.all_ids().size() == 2);

		// data_b is named by one record, data_a by two
		storage.truncate_from(b3.sequence() + 1);
		auto const dead = storage.remove_unreferenced_data();
		CHECK(dead == std::vector<data_id>{data_b.manifest_digest});
		CHECK(!table.find(data_b.manifest_digest));
		CHECK(table.find(data_a.manifest_digest));
		CHECK(storage.remove_unreferenced_data().empty());

		storage.truncate_from(b3.sequence());
		CHECK(storage.remove_unreferenced_data() == std::vector<data_id>{data_a.manifest_digest});
		CHECK(table.all_ids().empty());
	}

	SECTION("truncation drops the references") {
		auto const removed = storage.truncate_from(b3.sequence() + 1);
		CHECK(removed.size() == 2);
		CHECK(storage.data_reference_count(row_a->local_id) == 1);
		CHECK(storage.data_reference_count(row_b->local_id) == 0);
		// the row stays until the data store sweeps the unreferenced
		CHECK(table.find(data_b.manifest_digest));

		storage.truncate_prefix(b3.sequence() + 1, {});
		CHECK(storage.data_reference_count(row_a->local_id) == 0);
	}
}

// (RDS 9) the retention policy at a history cut: of the versions of an object below the
// cut the newest ones keep their data, the data only older ones name is superseded
TEST_CASE("record_storage superseded data below a cut", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	record_storage storage(db_conn);
	data_state_table table{db_conn};
	test_block_creator creator;

	auto const descriptor = [] { return data_descriptor{5080, 1000, securepath::test::random_octet_vector(64)}; };
	auto const ids = [](std::vector<data_descriptor> const& ds) {
		std::vector<data_id> ret;
		for(auto const& d : ds) {
			ret.push_back(d.manifest_digest);
		}
		return ret;
	};
	auto const a = util::create_object_id();
	auto const b = util::create_object_id();
	auto const d1 = descriptor(), d2 = descriptor(), d4 = descriptor(), d5 = descriptor();
	auto const e1 = descriptor(), e2 = descriptor();
	auto const commit = [&](std::vector<test_block_creator::version> versions) {
		auto const block = creator.test_versions(std::move(versions));
		REQUIRE(storage.create(block, record_state::in_sync));
		return block;
	};

	REQUIRE(storage.create(creator.test_user_change(), record_state::in_sync));
	auto const a1 = commit({{a, {}, d1}});
	auto const a2 = commit({{a, a1.tag(), d2}});
	auto const b1 = commit({{b, {}, e1}});
	// a change of the metadata only: not a version of the data
	auto const a3 = commit({{a, a2.tag(), std::nullopt}});
	// one record, two objects: it continues differently for each of them
	auto const both = commit({{a, a3.tag(), d4}, {b, b1.tag(), e2}});
	auto const segment = creator.test_segment();
	REQUIRE(storage.create(segment, record_state::in_sync));
	auto const cut = segment.sequence();
	// above the cut
	auto const a5 = commit({{a, both.tag(), d5}});

	SECTION("the versions beyond the kept ones") {
		CHECK(storage.superseded_data_below(cut, 1) == ids({d1, d2, e1}));
		CHECK(storage.superseded_data_below(cut, 2) == ids({d1}));
		CHECK(storage.superseded_data_below(cut, 3).empty());
		// the policy is not known, or keeps everything
		CHECK(storage.superseded_data_below(cut, 0).empty());
		CHECK(storage.superseded_data_below(cut, keep_all_data_versions).empty());
		// only what lies below the cut counts: there d2 is the newest data of a
		CHECK(storage.superseded_data_below(both.sequence(), 1) == ids({d1}));
		CHECK(storage.superseded_data_below(a1.sequence(), 1).empty());
		// the version above the cut supersedes nothing yet: it may still be rolled back
		// (in the order the data came to the storage)
		CHECK(storage.superseded_data_below(a5.sequence() + 1, 1) == ids({d1, d2, e1, d4}));
	}

	SECTION("every object is walked on its own") {
		// the retained set of the cut: b1 is reached through the record of both objects,
		// which the walk of a passed before
		auto const retained = storage.object_chain_tags_below(cut);
		for(auto const& block : {a1, a2, b1, a3, both}) {
			CHECK(std::find(retained.begin(), retained.end(), block.tag()) != retained.end());
		}
		CHECK(retained.size() == 5);
	}

	SECTION("somebody else naming the data keeps it") {
		// a newer version above the cut went back to the old data
		commit({{b, both.tag(), e1}});
		CHECK(storage.superseded_data_below(cut, 1) == ids({d1, d2}));
		// a record that is not in sync yet
		REQUIRE(storage.create(creator.test_versions({{util::create_object_id(), {}, d1}}).to_auth_record<data_change_record>()));
		CHECK(storage.superseded_data_below(cut, 1) == ids({d2}));
	}

	SECTION("an index marks them pruned") {
		auto const count = [&](data_descriptor const& d) {
			return storage.data_reference_count(table.find(d.manifest_digest)->local_id);
		};
		CHECK(storage.prune_superseded_data(cut, 2) == ids({d1}));
		CHECK(table.find(d1.manifest_digest)->state == record_data_state::pruned);
		CHECK(table.find(d2.manifest_digest)->state == record_data_state::deferred);
		// once
		CHECK(storage.prune_superseded_data(cut, 2).empty());
		CHECK(storage.prune_superseded_data(cut, 1) == ids({d2, e1}));
		CHECK(storage.superseded_data_below(cut, 1).empty());

		// the records and their references stay: nothing here is dead
		CHECK(storage.find_tag(a1.tag()));
		CHECK(count(d1) == 1);
		CHECK(storage.remove_unreferenced_data().empty());
		CHECK(table.all_ids().size() == 6);

		// a record naming a pruned data wants it again
		commit({{b, both.tag(), e1}});
		CHECK(table.find(e1.manifest_digest)->state == record_data_state::deferred);
		CHECK(count(e1) == 2);
		CHECK(storage.prune_superseded_data(cut, 1).empty());
	}
}

// (RDS 2) a database from before shared data rows had data_ref unique
TEST_CASE("record_storage upgrades the object table", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	db_conn->prepare("CREATE TABLE record_objects("
		"key INTEGER PRIMARY KEY,"
		"tag BLOB,"
		"prev_tag BLOB,"
		"oid BLOB,"
		"data_ref INTEGER UNIQUE);").execute();
	{
		auto q = db_conn->prepare("INSERT INTO record_objects(tag, oid) VALUES(:tag, :oid);");
		q.bind(":tag", octet_vector(16, 1));
		q.bind(":oid", octet_vector(16, 2));
		q.execute();
	}

	record_storage storage(db_conn);
	test_block_creator creator;
	data_descriptor const data{5080, 1000, securepath::test::random_octet_vector(64)};
	REQUIRE(storage.create(creator.test_user_change(), record_state::in_sync));
	REQUIRE(storage.create(creator.test_data_change_with_data(data), record_state::in_sync));
	REQUIRE(storage.create(creator.test_data_change_with_data(data), record_state::in_sync));
	CHECK(storage.data_reference_count(data_state_table{db_conn}.find(data.manifest_digest)->local_id) == 2);

	// the old rows came along
	auto q = db_conn->prepare("SELECT count(*) FROM record_objects WHERE tag = :tag;");
	q.bind(":tag", octet_vector(16, 1));
	CHECK(q.execute().value<std::int64_t>(0).value_or(-1) == 1);
	CHECK(!db_conn->has_table("record_objects_old"));
}

// (RDS 5) the storage's data servers are persisted next to the cursor owner and the limits
TEST_CASE("record_storage data endpoints persist", "[unit]") {
	remove_database_test_db();
	std::vector<data_endpoint> const endpoints{
		data_endpoint{"data1.example.org", 18203, crypto::public_key_id{securepath::test::random_octet_vector(32)}, "eu", {}},
		data_endpoint{"::1", 4711, crypto::public_key_id{securepath::test::random_octet_vector(32)}, {}, {}}};
	{
		record_storage storage(database::sqlite::create_sqlite_connection(db_name));
		CHECK(storage.data_endpoints().empty());
		storage.set_limits(storage_limits{16 * 1024, 512 * 1024});
		storage.set_data_endpoints(endpoints);
		CHECK(storage.data_endpoints() == endpoints);
	}
	record_storage storage(database::sqlite::create_sqlite_connection(db_name));
	CHECK(storage.data_endpoints() == endpoints);
	// neither setter clobbers the other's columns
	CHECK(storage.limits() == storage_limits{16 * 1024, 512 * 1024});
	storage.set_cursor_owner(octet_vector(32, 8));
	CHECK(storage.data_endpoints() == endpoints);
	storage.set_data_endpoints({});
	CHECK(storage.data_endpoints().empty());
	CHECK(storage.cursor_owner() == octet_vector(32, 8));
}

// (RDS 5) a client database from before the endpoint list gets the column
TEST_CASE("record_storage upgrades the sync state table", "[unit]") {
	remove_database_test_db();
	auto db_conn = database::sqlite::create_sqlite_connection(db_name);
	db_conn->prepare("CREATE TABLE sync_state("
		"key INTEGER PRIMARY KEY CHECK(key = 1),"
		"cursor_owner BLOB,"
		"max_record_size INTEGER,"
		"chunk_size INTEGER);").execute();
	{
		auto q = db_conn->prepare("INSERT INTO sync_state(key, cursor_owner, max_record_size, chunk_size) VALUES(1, :o, 4096, 262144);");
		q.bind(":o", octet_vector(32, 5));
		q.execute();
	}

	record_storage storage(db_conn);
	CHECK(storage.cursor_owner() == octet_vector(32, 5));
	CHECK(storage.limits() == storage_limits{4096, 262144});
	CHECK(storage.data_endpoints().empty());
	std::vector<data_endpoint> const endpoints{data_endpoint{"h", 1, crypto::public_key_id{securepath::test::random_octet_vector(32)}, {}, {}}};
	storage.set_data_endpoints(endpoints);
	CHECK(storage.data_endpoints() == endpoints);
}

}
