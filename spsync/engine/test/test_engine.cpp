#include <spsync/test/engine_context.hpp>

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::sync::util {

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

void check_user_change(serialised_record const& r, users const& expected_users) {
	r.deserialise_record(check_user_change_visitor{expected_users});
}

// * commit initial change
TEST_CASE("engine initial record", "[unit]") {
	test::engine_context context;

	context.io.add_commit_record_response([&](record_handle h)
		{
			users initial;
			initial.add(util::user_access{context.root_user, util::access_type::user_management_access});

			auto record = h->record();
			check_user_change(record, initial);
			record.set_server_sequence(sequence_number{1});
			return record;
		});

	context.create_initial_record();
	CHECK(context.io.process_event());
	CHECK(!context.io.process_event());

	CHECK(context.storage.last_sequence_number() == sequence_number{1});
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

	CHECK(!context.storage.last_sequence_number().is_valid());
	auto rhandle = context.storage.find_last();
	REQUIRE(rhandle);
	CHECK(rhandle->state() == record_state::pending_commit);
}

// * commit records after initial
TEST_CASE("engine commit multiple records", "[unit]") {
	test::engine_context context;

	for(int i = 0; i != 4; ++i) {
		context.io.add_commit_record_response([&](record_handle h)
			{
				auto record = h->record();
				record.set_server_sequence(context.io.next_sequence_number());
				return record;
			});
	}

	context.create_initial_record();
	context.engine.sync_object_change(create_object_id(), metadata{});
	context.engine.sync_object_change(create_object_id(), metadata{{"test", to_octet_vector("data")}});
	context.engine.sync_object_change(create_object_id(), metadata{});

	while(context.io.process_event()) {}

	CHECK(context.storage.last_sequence_number() == sequence_number{4});
	CHECK(context.storage.last_sequence_number() == context.io.current_sequence_number());
}

// * server does not accept the commit
// * server gives different sequence number
// * server return invalid record back
// * server pushes new records
// * fetch new records on beginning
// * create records with last seen sequence, when connecting, the server gives new records -> needs to recreate the queued records


}
