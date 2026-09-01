#include <spsync/test/test_sync_server.hpp>

#include <spsync/engine/history_verifier.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::sync {
using namespace securepath::sync::util;

namespace {

void commit_changes(test::test_sync_context& context, int amount) {
	for(int i = 0; i != amount; ++i) {
		context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	}
	while(context.handle_events()) {}
}

}

// fast verification pays crypto only for the tail and the backbone; the covered history
// is vouched by the authenticated tag lists (SEG 4 cost sanity)
TEST_CASE("history verification fast and full", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client();
	context.create_initial_record();
	while(context.handle_events()) {}

	commit_changes(context, 3);                              // seq 2..4
	context.client(0).engine.sync_segment_end(metadata{});   // seq 5, covers [1,5)
	while(context.handle_events()) {}
	commit_changes(context, 2);                              // seq 6..7
	context.client(0).engine.sync_segment_end(metadata{});   // seq 8, covers [5,8)
	while(context.handle_events()) {}
	commit_changes(context, 2);                              // seq 9..10
	REQUIRE(context.compare_record_storages(sequence_number{10}));

	// fast: two tail records and two segments carry the crypto cost, the other six
	// records are vouched by the coverage lists
	auto fast = context.client(0).engine.verify_history();
	REQUIRE(fast);
	CHECK(fast.value().verified_segments == 2);
	CHECK(fast.value().verified_records == 2);
	CHECK(fast.value().covered_records == 6);

	// full: every record is verified
	auto config = context.client(0).engine_config;
	config.verification = history_verification::full;
	context.client(0).engine.set_config(config);
	auto full = context.client(0).engine.verify_history();
	REQUIRE(full);
	CHECK(full.value().verified_segments == 2);
	CHECK(full.value().verified_records == 8);
	CHECK(full.value().covered_records == 0);
}

// without a segment the fast strategy falls back to the full walk
TEST_CASE("history verification without segments", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client();
	context.create_initial_record();
	while(context.handle_events()) {}
	commit_changes(context, 2);

	auto res = context.client(0).engine.verify_history();
	REQUIRE(res);
	CHECK(res.value().verified_records == 3);
	CHECK(res.value().verified_segments == 0);
	CHECK(res.value().covered_records == 0);
}

// a record replaced inside covered history no longer matches the authenticated segment
// tag list (SEG 4 tamper detection)
TEST_CASE("history verification detects tampered covered record", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client();
	context.create_initial_record();
	while(context.handle_events()) {}
	commit_changes(context, 2);                              // seq 2..3
	context.client(0).engine.sync_segment_end(metadata{});   // seq 4, covers [1,4)
	while(context.handle_events()) {}
	commit_changes(context, 1);                              // seq 5
	REQUIRE(context.client(0).engine.verify_history());

	// swap a covered record's tag underneath the storage
	auto q = context.client(0).database->prepare("UPDATE record SET tag = :t WHERE seq = :s;");
	q.bind(":t", securepath::test::random_octet_vector(16));
	q.bind(":s", std::uint64_t{2});
	q.execute();

	CHECK(context.client(0).engine.verify_history().is_error());
}

// a tampered record in the unsealed tail is caught by the full per-record verification
TEST_CASE("history verification detects tampered tail record", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client();
	context.create_initial_record();
	while(context.handle_events()) {}
	commit_changes(context, 2);                              // seq 2..3
	context.client(0).engine.sync_segment_end(metadata{});   // seq 4, covers [1,4)
	while(context.handle_events()) {}
	commit_changes(context, 1);                              // seq 5
	REQUIRE(context.client(0).engine.verify_history());

	// corrupt the stored block of the tail record
	auto q = context.client(0).database->prepare("UPDATE record SET record = :r WHERE seq = :s;");
	q.bind(":r", securepath::test::random_octet_vector(32));
	q.bind(":s", std::uint64_t{5});
	q.execute();

	CHECK(context.client(0).engine.verify_history().is_error());
}

}
