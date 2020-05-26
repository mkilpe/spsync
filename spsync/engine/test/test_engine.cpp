#include <spsync/test/engine_context.hpp>

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::sync::util {
namespace {
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
			record.set_server_sequence_and_parent_hash(context.io.next_sequence_number(), context.io.previous_block_hash());
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

// * commit not accepted
/*TEST_CASE("engine commit not accepted", "[unit]") {
	test::engine_context context;
	context.add_default_commit_response();
	context.create_initial_record();
	CHECK(context.io.process_event());


}*/

// * bad sequence number is returned for record
TEST_CASE("engine bad sequence", "[unit]") {
	test::engine_context context;
	context.add_default_commit_response();
	context.io.add_commit_record_response([&](record_handle h)
			{
				auto record = h->record();
				record.set_server_sequence_and_parent_hash(++context.io.next_sequence_number(), context.io.previous_block_hash());
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
				record.set_server_sequence_and_parent_hash(context.io.next_sequence_number(), securepath::test::random_octet_vector(32));
				return record;
			});
	context.io.add_commit_record_response([&](record_handle h)
			{
				auto record = h->record();
				record.set_server_sequence_and_parent_hash(sequence_number{10}, securepath::test::random_octet_vector(32));
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


// * server return invalid record back
// * server pushes new records
// * fetch new records on beginning
// * create records with last seen sequence, when connecting, the server gives new records -> needs to recreate the queued records


}
