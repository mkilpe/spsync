#include <spsync/test/test_sync_server.hpp>

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::sync {
using namespace securepath::sync::util;

// + (1) single client sync records (allow all mode)
// + (2) two clients, one commits records (allow all mode)
// + (3) multi client set-up where all commits (allow all mode)
// + (4) two clients, one commits records while other is off-line and then goes on-line (allow all mode)
// - (5) two clients, one out of sync with seq -> fails (conflict)
// - (6) two clients both try to commit follow up for record -> one fails (conflict)
// - (7) multi client set-up where all commits (other modes than allow all)
// - (8) two clients, one is off-line and does changes and goes then on-line

// (1) single client sync records (allow all mode)
TEST_CASE("engine sync single client", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	context.add_client();
	context.create_initial_record();
	context.handle_events();
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.handle_events();
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.handle_events();
	CHECK(context.compare_record_storages(sequence_number{4}));
}

// (2) two clients, one commits records (allow all mode)
TEST_CASE("engine sync two clients with one committing", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	context.add_client(true, 2);
	context.create_initial_record();
	context.handle_events();
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.handle_events();
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.handle_events();
	CHECK(context.compare_record_storages(sequence_number{4}));
}

// (3) multi client set-up where all commits (allow all mode)
TEST_CASE("engine sync multi-client committing", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	context.add_client(true, 10);
	context.create_initial_record();
	context.handle_events();
	for(int i = 0; i != 10; ++i) {
		for(int c = 0; c != 10; ++c) {
			context.client(c).engine.sync_object_change(create_object_id(), metadata{});
		}
	}
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{101}));
}

// (4) two clients, one commits records while other is off-line and then goes on-line (allow all mode)
TEST_CASE("engine sync client off-line on-line", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	context.add_client(false, 2);
	context.connect_client(0);
	context.create_initial_record();
	context.handle_events();
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.handle_events();
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.handle_events();
	context.connect_client(1);
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{4}));
}

// (5) two clients, one out of sync with seq -> fails (conflict)
TEST_CASE("engine sync two clients with seq conflict", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client(true, 2);
	context.create_initial_record();
	context.handle_events();
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.handle_events();
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.client(1).engine.sync_object_change(create_object_id(), metadata{});
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{4}));
}


}
