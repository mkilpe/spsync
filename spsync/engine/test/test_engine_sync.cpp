#include <spsync/test/test_sync_server.hpp>

#include <spsync/client/record_util.hpp>
#include <spsync/engine/record_creator.hpp>

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::sync {
using namespace securepath::sync::util;

namespace {

/// engine output observer counting object conflicts (events arrive on the loop thread)
struct conflict_observer : engine_output {
	using engine_output::engine_output;
	~conflict_observer() { stop_handler(); }

	void on_object_conflict(record_handle local, record_handle remote) override {
		last_local = local;
		last_remote = remote;
		++conflicts;
	}

	std::atomic<int> conflicts{0};
	record_handle last_local;
	record_handle last_remote;
};

}

// + (1) single client sync records (allow all mode)
// + (2) two clients, one commits records (allow all mode)
// + (3) multi client set-up where all commits (allow all mode)
// + (4) two clients, one commits records while other is off-line and then goes on-line (allow all mode)
// + (5) two clients, one out of sync with seq -> fails (out of sync)
// + (6) three clients, pushing changes -> all in sync at the end
// + (7) single client sync multiple records (require all seen mode)
// + (8) disconnect/connect with pending commits
// + (9) sync new records after disconnect/connect
// - () two clients, both push new enc key at the same time (require all seen mode)
// - () two clients both try to commit follow up for record -> one fails (conflict)
// - () multi client set-up where all commits (other modes than allow all)
// - () two clients, one is off-line and does changes and goes then on-line

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
	auth_mode amode = GENERATE(auth_mode::only_tag, auth_mode::sign_records);

	test::test_sync_context context(chain_sync_config{sync_mode::allow_all, amode});
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

// (5) two clients, one out of sync with seq -> fails (out of sync)
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

// (6) three clients, pushing changes -> all in sync at the end
TEST_CASE("engine sync three clients conflict", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client(true, 3);
	context.create_initial_record();
	context.handle_events();

	for(int i = 0; i != 100; ++i) {
		for(int c = 0; c != 3; ++c) {
			context.client(c).engine.sync_object_change(create_object_id(), metadata{});
		}
	}

	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{301}));
}

// (7) single client sync multiple records (require all seen mode)
TEST_CASE("engine sync single client multi", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client();
	context.create_initial_record();
	for(int i = 0; i != 5; ++i) {
		context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	}
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{6}));
}

// (8) disconnect/connect with pending commits
TEST_CASE("engine sync pending after disconnect/connect", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}
	context.disconnect_client(0);
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	while(context.handle_events()) {}
	context.connect_client(0);
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{2}));
}

// (9) sync new records after disconnect/connect
TEST_CASE("sync new records after disconnect/connect", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}
	context.disconnect_client(0);
	context.client(1).engine.sync_object_change(create_object_id(), metadata{});
	while(context.handle_events()) {}
	context.connect_client(0);
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{2}));
}


// (10) two clients in require_special_seen mode; a data change that has not seen the newest
// special record is rejected by the server and rebased by the engine
TEST_CASE("engine sync special seen mode rebase", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_special_seen});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}

	// client 0 commits a new special record; client 1 commits a data change that is
	// based on the old head and so has not seen it
	users delta{users_change_mode::delta};
	delta.add(util::user_access{context.client(1).user, util::access_type::data_write_access});
	context.client(0).engine.sync_user_change(encrypt_last_key_for_users(delta, context.client(0).cc));
	auto h = context.client(1).engine.sync_object_change(util::create_object_id(), metadata{});
	auto original_tag = h->tag();

	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{3}));
	// the data change was rebuilt on top of the special record
	CHECK(h->tag() != original_tag);
	CHECK(!context.server.sync.records().find_tag(original_tag));
	CHECK(context.server.sync.records().find_tag(h->tag()));
}

// (11) two clients in require_data_add_remove_seen mode; an add that has not seen the newest
// add is rejected and rebased
TEST_CASE("engine sync data add seen mode rebase", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_data_add_remove_seen});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}

	context.client(0).engine.sync_object_change(util::create_object_id(), metadata{});
	auto h = context.client(1).engine.sync_object_change(util::create_object_id(), metadata{});
	auto original_tag = h->tag();

	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{3}));
	CHECK(h->tag() != original_tag);
	CHECK(context.server.sync.records().find_tag(h->tag()));
}

// (12) allow_all never rebuilds a record just because the head moved
TEST_CASE("engine sync allow_all does not rebuild", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}

	// both clients commit concurrently; neither has seen the other's record
	auto h0 = context.client(0).engine.sync_object_change(util::create_object_id(), metadata{});
	auto h1 = context.client(1).engine.sync_object_change(util::create_object_id(), metadata{});
	auto tag0 = h0->tag();
	auto tag1 = h1->tag();

	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{3}));
	// the records were committed exactly as created
	CHECK(h0->tag() == tag0);
	CHECK(h1->tag() == tag1);
	CHECK(context.server.sync.records().find_tag(tag0));
	CHECK(context.server.sync.records().find_tag(tag1));
}


// (13) two clients change the same object concurrently; the later one is rebased on top
// and the conflict is reported, in every mode
TEST_CASE("engine sync object conflict rebase", "[unit]") {
	auto mode = GENERATE(sync_mode::allow_all, sync_mode::require_special_seen,
		sync_mode::require_data_add_remove_seen, sync_mode::require_all_seen);

	test::test_sync_context context(chain_sync_config{mode});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}

	auto oid = create_object_id();
	context.client(0).engine.sync_object_change(oid, metadata{});
	while(context.handle_events()) {}

	conflict_observer observer{context.client(1).single_thread_event_loop};
	context.client(1).engine.set_output(&observer);

	// both change the same object; client 0 wins the race and client 1 is rebased
	context.client(0).engine.sync_object_change(oid, metadata{});
	auto h = context.client(1).engine.sync_object_change(oid, metadata{});
	auto original_tag = h->tag();
	while(context.handle_events()) {}

	CHECK(context.compare_record_storages(sequence_number{4}));
	CHECK(h->tag() != original_tag);
	CHECK(context.server.sync.records().find_tag(h->tag()));
	WAIT_CHECK(observer.conflicts == 1, 2s);
	context.client(1).engine.set_output(nullptr);
}

// (14) with the ask policy the conflicting record is cancelled and reported once
TEST_CASE("engine sync object conflict ask policy", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}

	auto oid = create_object_id();
	context.client(0).engine.sync_object_change(oid, metadata{});
	while(context.handle_events()) {}

	auto config = context.client(1).engine_config;
	config.conflicts = conflict_policy::ask;
	context.client(1).engine.set_config(config);

	conflict_observer observer{context.client(1).single_thread_event_loop};
	context.client(1).engine.set_output(&observer);

	context.client(0).engine.sync_object_change(oid, metadata{});
	auto h = context.client(1).engine.sync_object_change(oid, metadata{});
	while(context.handle_events()) {}

	// the conflicting record was cancelled: the server only has client 0's change
	CHECK(context.compare_record_storages(sequence_number{3}));
	CHECK(h->state() == record_state::invalid);
	WAIT_CHECK(observer.conflicts == 1, 2s);
	CHECK(observer.conflicts == 1);
	context.client(1).engine.set_output(nullptr);
}


// (15) a pending record with several changes where only a subset conflicts: the rebuild
// keeps the non-conflicting changes and one conflict event fires per conflicting object
TEST_CASE("engine sync multi change record partial conflict", "[unit]") {
	auto mode = GENERATE(sync_mode::allow_all, sync_mode::require_all_seen);

	test::test_sync_context context(chain_sync_config{mode});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}

	auto oid_a = create_object_id();
	auto oid_b = create_object_id();
	auto oid_c = create_object_id();
	context.client(0).engine.sync_object_change(oid_a, metadata{});
	context.client(0).engine.sync_object_change(oid_b, metadata{});
	context.client(0).engine.sync_object_change(oid_c, metadata{});
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{4}));

	// client 1 goes off-line holding a pending multi change record over a, b and c
	context.disconnect_client(1);
	auto& storage1 = context.client(1).io.records();
	auto tag_a = storage1.find_last(oid_a)->tag();
	auto tag_b = storage1.find_last(oid_b)->tag();
	auto tag_c = storage1.find_last(oid_c)->tag();
	data_change_record_creator creator(context.client(1).enc_keys.current_key(), storage1.last_block());
	creator.add_change(oid_a, tag_a, metadata{});
	creator.add_change(oid_b, tag_b, metadata{});
	creator.add_change(oid_c, tag_c, metadata{});
	auto h = storage1.create(creator.result());
	auto original_tag = h->tag();

	// meanwhile b and c move underneath it
	context.client(0).engine.sync_object_change(oid_b, metadata{});
	context.client(0).engine.sync_object_change(oid_c, metadata{});
	while(context.handle_events()) {}
	auto new_tag_b = context.client(0).io.records().find_last(oid_b)->tag();
	auto new_tag_c = context.client(0).io.records().find_last(oid_c)->tag();

	conflict_observer observer{context.client(1).single_thread_event_loop};
	context.client(1).engine.set_output(&observer);

	context.connect_client(1);
	while(context.handle_events()) {}

	CHECK(context.compare_record_storages(sequence_number{7}));
	CHECK(h->tag() != original_tag);
	auto committed = context.server.sync.records().find_tag(h->tag());
	REQUIRE(committed);

	// the rebuilt record keeps the non-conflicting change and rebases the conflicting ones
	auto rec = committed->record().deserialise_to<data_change_record>();
	std::map<object_id, record_tag> previous;
	for(auto const& c : rec) {
		previous[c.data.id] = c.data.previous_oid_record_tag;
	}
	REQUIRE(previous.size() == 3);
	CHECK(previous[oid_a] == tag_a);
	CHECK(previous[oid_b] == new_tag_b);
	CHECK(previous[oid_c] == new_tag_c);

	// one conflict event per conflicting object
	WAIT_CHECK(observer.conflicts == 2, 2s);
	CHECK(observer.conflicts == 2);
	context.client(1).engine.set_output(nullptr);
}


// (16) the commit storm: every client commits a batch without waiting, in every mode;
// this is the regression net for the whole weak/strict mode handling
TEST_CASE("engine sync commit storm", "[unit]") {
	auto mode = GENERATE(sync_mode::allow_all, sync_mode::require_special_seen,
		sync_mode::require_data_add_remove_seen, sync_mode::require_all_seen);

	int const clients = 5;
	int const per_client = 10;
	test::test_sync_context context(chain_sync_config{mode});
	context.add_client(true, clients);
	context.create_initial_record();
	while(context.handle_events()) {}

	context.commit_storm(per_client);
	CHECK(context.compare_record_storages(sequence_number{1 + clients*per_client}));
}

// (17) the commit storm with a membership change dropped in halfway: the special record
// forces every in-flight record behind it to rebase in the special/data-add modes
TEST_CASE("engine sync commit storm with special record", "[unit]") {
	auto mode = GENERATE(sync_mode::allow_all, sync_mode::require_special_seen,
		sync_mode::require_data_add_remove_seen, sync_mode::require_all_seen);

	int const clients = 5;
	int const per_client = 10;
	test::test_sync_context context(chain_sync_config{mode});
	context.add_client(true, clients);
	context.create_initial_record();
	while(context.handle_events()) {}

	context.commit_storm(per_client, true);
	CHECK(context.compare_record_storages(sequence_number{2 + clients*per_client}));
}

}
