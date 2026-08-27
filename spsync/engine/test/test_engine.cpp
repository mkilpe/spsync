#include <spsync/test/engine_context.hpp>

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::sync::util {
namespace {

// + (1) commit initial change
// + (2) initial change gives error
// / (3) commit records after initial
// + (4) bad sequence number is returned for record
// + (5) bad parent hash is returned for record
// / (6) commit not accepted
// - (7) server return invalid record back
// - (8) server pushes new records
// - (9) fetch new records on beginning
// - (10) create records with last seen sequence, when connecting, the server gives new records -> needs to recreate the queued records

struct check_user_change_visitor {
	users expected_users;

	void operator()(user_change_record const& r) const {
		CHECK(r.data().access() == expected_users);
	}

	template<typename Record>
	void operator()(Record const&) const {
		CHECK(false);
	}
};

void check_user_change(chain_block const& r, users const& expected_users) {
	r.deserialise_record(check_user_change_visitor{expected_users});
}
}

// * commit initial change
TEST_CASE("engine initial record", "[unit]") {
	test::engine_context context;

	// check the initial user change record is correct
	context.io.add_commit_record_response([&](record_handle h)
		{
			users initial;
			initial.add(util::user_access{context.root_user, util::access_type::user_management_access});

			auto record = h->record();
			check_user_change(record, initial);
			record.set_sequence_and_parent_hash(context.io.next_sequence_number(), context.io.previous_block_hash());
			return record;
		});

	context.create_initial_record();
	CHECK(context.io.process_event());
	CHECK(!context.io.process_event());

	CHECK(context.storage.last_block().sequence == sequence_number{1});

	auto rhandle = context.storage.find_last();
	REQUIRE(rhandle);
	CHECK(rhandle->state() == record_state::in_sync);
}

// * initial change gives error
// t: check for correct error when error handling properly implemented for sync engine
TEST_CASE("engine initial record results an error", "[unit]") {
	test::engine_context context;

	context.io.add_commit_record_response([&](record_handle h)
		{
			return make_error(securepath::errc::unknown_error, "test error");
		});

	context.create_initial_record();
	CHECK(context.io.process_event());
	CHECK(!context.io.process_event());

	CHECK(!context.storage.last_block().is_valid());
	REQUIRE(!context.storage.find_last());
}

// * commit records after initial
TEST_CASE("engine commit multiple records", "[unit]") {
	test::engine_context context;

	for(int i = 0; i != 4; ++i) {
		context.add_default_commit_response();
	}

	context.create_initial_record();
	context.io.process_event();
	context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_event();
	context.engine.sync_object_change(create_object_id(), metadata{{"test", to_octet_vector("data")}});
	context.io.process_event();
	context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_event();

	auto handle = context.storage.find_last();
	REQUIRE(handle);
	CHECK(context.storage.last_block().sequence == sequence_number{4});
	auto previous_handle = context.storage.find(handle->parent_block_hash());
	REQUIRE(previous_handle);
	CHECK(previous_handle->block_id().sequence == sequence_number{3});
	CHECK(previous_handle->block_id().hash == handle->parent_block_hash());

	while(handle) {
		CHECK(handle->state() == record_state::in_sync);
		handle = context.storage.find(handle->parent_block_hash());
	}
}

// * bad sequence number is returned for record
TEST_CASE("engine bad sequence", "[unit]") {
	test::engine_context context;
	context.add_default_commit_response();
	context.io.add_commit_record_response([&](record_handle h)
			{
				auto record = h->record();
				record.set_sequence_and_parent_hash(++context.io.next_sequence_number(), context.io.previous_block_hash());
				return record;
			});

	context.create_initial_record();
	context.io.process_event();
	auto rec_handle = context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_event();

	REQUIRE(context.storage.find_last());

	// only committing the first change worked
	CHECK(context.storage.last_block().sequence == sequence_number{1});
	CHECK(context.storage.find_last()->state() == record_state::in_sync);

	CHECK(rec_handle->state() == record_state::invalid);
}

// * bad parent hash is returned for record
TEST_CASE("engine bad parent hash", "[unit]") {
	test::engine_context context;
	context.add_default_commit_response();
	context.io.add_commit_record_response([&](record_handle h)
			{
				auto record = h->record();
				record.set_sequence_and_parent_hash(context.io.next_sequence_number(), securepath::test::random_octet_vector(32));
				return record;
			});
	context.io.add_commit_record_response([&](record_handle h)
			{
				auto record = h->record();
				record.set_sequence_and_parent_hash(sequence_number{10}, securepath::test::random_octet_vector(32));
				return record;
			});


	context.create_initial_record();
	context.io.process_event();
	auto rec_handle1 = context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_event();
	auto rec_handle2 = context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_event();

	REQUIRE(context.storage.find_last());

	// only committing the first change worked
	CHECK(context.storage.last_block().sequence == sequence_number{1});
	CHECK(context.storage.find_last()->state() == record_state::in_sync);

	// the parent hash is wrong and the sequence number is what we expect next == error
	CHECK(rec_handle1->state() == record_state::invalid);

	CHECK(rec_handle2->state() == record_state::pending_sync);
}

// * commit not accepted
// t: check to retry for non-fatal errors when implemented
TEST_CASE("engine commit not accepted", "[unit]") {
	test::engine_context context;
	context.add_default_commit_response();
	context.create_initial_record();
	CHECK(context.io.process_event());

	context.io.add_commit_record_response([&](record_handle h)
		{
			return make_error(securepath::errc::unknown_error, "test error");
		});

	auto rec_handle = context.engine.sync_object_change(create_object_id(), metadata{});
	context.io.process_event();

	REQUIRE(context.storage.find_last());

	// only committing the first change worked
	CHECK(context.storage.last_block().sequence == sequence_number{1});
	CHECK(context.storage.find_last()->state() == record_state::in_sync);

	// commit failed, so it is still pending
	CHECK(rec_handle->state() == record_state::pending_commit);
}


namespace {

/// build a chain of one initial user change plus data changes in a source context and
/// return the committed blocks so they can be fed to another engine in arbitrary order
std::deque<chain_block> build_test_chain(test::engine_context& source, int data_changes) {
	for(int i = 0; i != data_changes + 1; ++i) {
		source.add_default_commit_response();
	}
	source.create_initial_record();
	source.io.process_events();
	for(int i = 0; i != data_changes; ++i) {
		source.engine.sync_object_change(create_object_id(), metadata{});
		source.io.process_events();
	}
	std::deque<chain_block> blocks;
	for(sequence_number seq{1}; seq <= source.storage.last_block().sequence; ++seq) {
		auto h = source.storage.find(seq);
		auto block = h->record();
		// the stored client blob keeps the predicted sequence and empty parent hash (see
		// plan defect B8); bake in the server assigned block id so the chain is linked
		block.set_sequence_and_parent_hash(h->block_id().sequence, h->parent_block_hash());
		blocks.push_back(block);
	}
	return blocks;
}

void insert_test_key(test::engine_context& context) {
	context.enc_keys.insert(encryption_key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")});
}

}

// * weak modes accept authentic blocks out of order and with gaps
TEST_CASE("engine weak mode accepts out of order blocks", "[unit]") {
	auto mode = GENERATE(sync_mode::allow_all, sync_mode::require_special_seen, sync_mode::require_data_add_remove_seen);

	test::engine_context source;
	auto blocks = build_test_chain(source, 3);
	REQUIRE(blocks.size() == 4);

	test::engine_context target{sync_engine_config{.mode=mode}};
	insert_test_key(target);

	target.engine.on_record_received(blocks[0]); // root
	target.engine.on_record_received(blocks[3]); // gap: 4 before 2 and 3
	CHECK(target.storage.find(sequence_number{4}));
	target.engine.on_record_received(blocks[2]);
	CHECK(target.storage.find(sequence_number{3}));
	target.engine.on_record_received(blocks[1]);

	for(sequence_number seq{1}; seq <= sequence_number{4}; ++seq) {
		auto h = target.storage.find(seq);
		REQUIRE(h);
		CHECK(h->state() == record_state::in_sync);
	}
	CHECK(target.storage.last_block().sequence == sequence_number{4});
}

// * strict mode still requires the chain to be contiguous
TEST_CASE("engine strict mode keeps out of order blocks pending", "[unit]") {
	test::engine_context source;
	auto blocks = build_test_chain(source, 3);
	REQUIRE(blocks.size() == 4);

	test::engine_context target; // require_all_seen
	insert_test_key(target);

	target.engine.on_record_received(blocks[0]);
	target.engine.on_record_received(blocks[3]);
	// the gap keeps the block out of the chain
	CHECK(!target.storage.find(sequence_number{4}));
	CHECK(target.storage.find(sequence_number{4}, record_state::pending_sync));
	target.engine.on_record_received(blocks[2]);
	CHECK(!target.storage.find(sequence_number{3}));

	// filling the gap promotes the pending blocks
	target.engine.on_record_received(blocks[1]);
	for(sequence_number seq{1}; seq <= sequence_number{4}; ++seq) {
		auto h = target.storage.find(seq);
		REQUIRE(h);
		CHECK(h->state() == record_state::in_sync);
	}
}

// * weak modes reject a different block for an already used sequence
TEST_CASE("engine weak mode rejects conflicting sequence", "[unit]") {
	test::engine_context source;
	auto blocks = build_test_chain(source, 2);
	REQUIRE(blocks.size() == 3);

	test::engine_context target{sync_engine_config{.mode=sync_mode::allow_all}};
	insert_test_key(target);

	target.engine.on_record_received(blocks[0]);
	target.engine.on_record_received(blocks[1]);

	// a different (authentic) block claiming an already used sequence must not replace it
	auto conflicting = blocks[2];
	conflicting.set_sequence_and_parent_hash(sequence_number{2}, blocks[0].hash());
	target.engine.on_record_received(conflicting);

	auto h = target.storage.find(sequence_number{2});
	REQUIRE(h);
	CHECK(h->tag() == blocks[1].tag());
	auto rejected = target.storage.find_tag(conflicting.tag());
	REQUIRE(rejected);
	CHECK(rejected->state() == record_state::invalid);
}

}
