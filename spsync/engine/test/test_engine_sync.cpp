#include <spsync/test/test_sync_server.hpp>

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::sync::util {

// - (1) single client sync records
// - (2) two clients, one commits records
// - (3) two clients, one commits records while other is offline and then goes online
// - (4) two clients both commit separate records
// - (5) two clients both try to commit follow up for record -> one fails (conflict)
// - (6) multi client set-up where one commits
// - (7) multi client set-up where all commits

TEST_CASE("engine sync test 1", "[unit]") {
	test::test_sync_context context;
	context.add_client();
	context.create_initial_record();
	context.handle_events();
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	context.handle_events();
	CHECK(context.compare_record_storages(sequence_number{2}));
}

}
