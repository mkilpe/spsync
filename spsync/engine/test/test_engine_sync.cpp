#include <spsync/test/test_sync_server.hpp>
#include <spsync/test/test_block_creator.hpp>

#include <spsync/client/record_util.hpp>
#include <spsync/engine/record_creator.hpp>
#include <spsync/engine/record_verifier.hpp>

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
	auto original_op = h->record().deserialise_to<data_change_record>().op_id();
	while(context.handle_events()) {}

	CHECK(context.compare_record_storages(sequence_number{4}));
	CHECK(h->tag() != original_tag);
	CHECK(context.server.sync.records().find_tag(h->tag()));
	// the rebase preserved the operation id
	CHECK(h->record().deserialise_to<data_change_record>().op_id() == original_op);
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

// (18) segment end covers the chain since the previous segment, in every mode (SEG 2)
TEST_CASE("engine sync segment end", "[unit]") {
	auto mode = GENERATE(sync_mode::allow_all, sync_mode::require_special_seen,
		sync_mode::require_data_add_remove_seen, sync_mode::require_all_seen);

	test::test_sync_context context(chain_sync_config{mode});
	context.add_client();
	context.create_initial_record();
	while(context.handle_events()) {}

	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	while(context.handle_events()) {}

	// a segment seals only committed history: refused while a commit is pending
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	CHECK_THROWS(context.client(0).engine.sync_segment_end(metadata{}));
	while(context.handle_events()) {}

	metadata meta;
	meta.insert("checkpoint", std::string{"test"});
	auto h = context.client(0).engine.sync_segment_end(meta);
	REQUIRE(h);
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{4}));

	auto seg = h->record().deserialise_to<segment_record>();
	CHECK(h->block_id().sequence == sequence_number{4});
	CHECK(seg.data().segment_start() == sequence_number{1});
	CHECK(seg.data().segment_end() == sequence_number{4});
	CHECK(seg.data().previous_segment_tag().empty());
	REQUIRE(seg.data().tags().size() == 3);
	for(std::size_t i = 0; i != seg.data().tags().size(); ++i) {
		CHECK(seg.data().tags()[i] == context.server.sync.records().find(sequence_number{i + 1})->tag());
	}

	// the encrypted header carries the metadata and the record verifies
	segment_record_verifier ver(context.client(0).enc_keys.current_key(), seg, h->record().auth());
	CHECK(ver.is_authentic());
	CHECK(ver.header().metadata().find<std::string>("checkpoint") == std::string{"test"});

	// the next segment starts where the first ended and links it by tag (the backbone)
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	while(context.handle_events()) {}
	auto h2 = context.client(0).engine.sync_segment_end(metadata{});
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{6}));

	auto seg2 = h2->record().deserialise_to<segment_record>();
	CHECK(seg2.data().segment_start() == sequence_number{4});
	CHECK(seg2.data().segment_end() == sequence_number{6});
	CHECK(seg2.data().previous_segment_tag() == h->tag());
	REQUIRE(seg2.data().tags().size() == 2);
	CHECK(seg2.data().tags()[0] == h->tag());
}

// (19) a segment that has not seen the newest record is rejected and rebuilt with a
// recomputed range and tag list, preserving the operation id (SEG 2)
TEST_CASE("engine sync segment conflict rebase", "[unit]") {
	auto mode = GENERATE(sync_mode::require_special_seen,
		sync_mode::require_data_add_remove_seen, sync_mode::require_all_seen);

	test::test_sync_context context(chain_sync_config{mode});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}

	// client 0 wins the race; client 1's segment is based on the old head
	auto winner = context.client(0).engine.sync_object_change(create_object_id(), metadata{});
	auto h = context.client(1).engine.sync_segment_end(metadata{});
	auto original_tag = h->tag();
	auto original_op = h->record().deserialise_to<segment_record>().op_id();
	CHECK(h->record().deserialise_to<segment_record>().data().segment_end() == sequence_number{2});

	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{3}));
	CHECK(h->tag() != original_tag);
	CHECK(!context.server.sync.records().find_tag(original_tag));

	auto seg = h->record().deserialise_to<segment_record>();
	CHECK(seg.op_id() == original_op);
	CHECK(seg.data().segment_start() == sequence_number{1});
	CHECK(seg.data().segment_end() == sequence_number{3});
	REQUIRE(seg.data().tags().size() == 2);
	CHECK(seg.data().tags()[1] == winner->tag());
}

// (20) rejoin from the anchor after a server-side history cut (segments plan SEG 5): the
// new client gets the anchor, the tail and the retained object chains, nothing else
TEST_CASE("engine sync rejoin from anchor after cut", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client();
	context.create_initial_record();
	while(context.handle_events()) {}

	auto oid = create_object_id();
	context.client(0).engine.sync_object_change(oid, metadata{});                 // 2: add A
	while(context.handle_events()) {}
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});  // 3: add B
	while(context.handle_events()) {}
	context.client(0).engine.sync_object_change(oid, metadata{});                 // 4: change A
	while(context.handle_events()) {}
	auto seg = context.client(0).engine.sync_segment_end(metadata{});             // 5: covers [1,5)
	while(context.handle_events()) {}
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});  // 6
	while(context.handle_events()) {}
	REQUIRE(context.compare_record_storages(sequence_number{6}));

	// the server cuts before the segment: the root user change goes, the object chains stay
	auto removed = context.server.sync.log().cut_before(seg->tag());
	REQUIRE(removed.size() == 1);
	CHECK(removed[0].sequence() == sequence_number{1});

	// a new client joins with the anchor hash and the keys from the invite (the root
	// record that used to carry the enveloped keys is gone)
	context.add_client(false, 1);
	auto& fresh = context.client(1);
	auto cfg = fresh.engine_config;
	cfg.trusted_anchor = seg->block_id().hash;
	fresh.engine.set_config(cfg);
	fresh.enc_keys.insert(encryption_key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")});
	context.connect_client(1);
	while(context.handle_events()) {}

	// the sparse history synced: retained records promoted, anchor as the chain start
	auto& recs = fresh.io.records();
	CHECK(recs.last_block().sequence == sequence_number{6});
	CHECK(!recs.find(sequence_number{1}));
	CHECK(recs.find(sequence_number{2}));
	CHECK(recs.find(sequence_number{4}));
	REQUIRE(recs.find(sequence_number{5}));
	CHECK(recs.find(sequence_number{5})->tag() == seg->tag());
	CHECK(recs.find(sequence_number{6}));
	REQUIRE(recs.find_last(oid));
	CHECK(recs.find_last(oid)->tag() == recs.find(sequence_number{4})->tag());

	// verification anchors at the segment: retained records detached, tail chained
	auto fast = fresh.engine.verify_history();
	REQUIRE(fast);
	CHECK(fast.value().verified_segments == 1);
	CHECK(fast.value().verified_records == 4);
	CHECK(fast.value().covered_records == 0);
	cfg.verification = history_verification::full;
	fresh.engine.set_config(cfg);
	auto full = fresh.engine.verify_history();
	REQUIRE(full);
	CHECK(full.value().verified_segments == 1);
	CHECK(full.value().verified_records == 4);

	// the rejoined client changes a retained object and everyone converges
	fresh.engine.sync_object_change(oid, metadata{});                             // 7
	while(context.handle_events()) {}
	CHECK(context.server.sync.current_sequence_number() == sequence_number{7});
	CHECK(recs.find(sequence_number{7}));
	CHECK(context.client(0).io.records().find(sequence_number{7}));
}

// (21) local prune at a segment (segments plan SEG 6): the client drops covered history
// while the server keeps everything; verification and syncing continue from the anchor
TEST_CASE("engine sync local prune at segment", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}

	// pruning needs a committed segment
	CHECK_THROWS(context.client(0).engine.prune_history());

	auto oid = create_object_id();
	context.client(0).engine.sync_object_change(oid, metadata{});                 // 2: add A
	while(context.handle_events()) {}
	context.client(0).engine.sync_object_change(oid, metadata{});                 // 3: change A
	while(context.handle_events()) {}
	auto seg = context.client(0).engine.sync_segment_end(metadata{});             // 4: covers [1,4)
	while(context.handle_events()) {}
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});  // 5
	while(context.handle_events()) {}
	REQUIRE(context.compare_record_storages(sequence_number{5}));

	CHECK_THROWS(context.client(0).engine.prune_history(securepath::test::random_octet_vector(16)));

	// client 0 prunes at the newest segment; the server and client 1 keep everything
	auto anchor = context.client(0).engine.prune_history();
	CHECK(anchor == seg->block_id().hash);

	auto& recs = context.client(0).io.records();
	CHECK(!recs.find(sequence_number{1}));
	CHECK(recs.find(sequence_number{2}));
	CHECK(recs.find(sequence_number{3}));
	CHECK(recs.find(sequence_number{4}));
	CHECK(recs.find(sequence_number{5}));
	CHECK(context.server.sync.records().find(sequence_number{1}));

	// verification works from the anchor right away...
	auto fast = context.client(0).engine.verify_history();
	REQUIRE(fast);
	CHECK(fast.value().verified_segments == 1);
	CHECK(fast.value().verified_records == 3);
	CHECK(fast.value().covered_records == 0);
	// ...and on a reload where the app supplies the persisted anchor
	auto cfg = context.client(0).engine_config;
	cfg.trusted_anchor = anchor;
	cfg.verification = history_verification::full;
	context.client(0).engine.set_config(cfg);
	REQUIRE(context.client(0).engine.verify_history());

	// both sides keep working: the pruned client and the full client converge
	context.client(0).engine.sync_object_change(oid, metadata{});                 // 6
	while(context.handle_events()) {}
	context.client(1).engine.sync_object_change(create_object_id(), metadata{});  // 7
	while(context.handle_events()) {}
	CHECK(context.server.sync.current_sequence_number() == sequence_number{7});
	CHECK(recs.find(sequence_number{7}));
	CHECK(context.client(1).io.records().find(sequence_number{6}));
}

// (22) replica switch (plan 4.5): connecting to another replica of the same storage in a
// weak mode refetches from the start, dedups by tag/op and adopts the new cursor; a
// record only known locally is committed to the new replica
TEST_CASE("engine sync replica switch", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_special_seen});
	context.add_client();
	context.create_initial_record();
	while(context.handle_events()) {}

	auto oid = create_object_id();
	context.client(0).engine.sync_object_change(oid, metadata{});                  // A: 2
	while(context.handle_events()) {}
	context.client(0).engine.sync_object_change(create_object_id(), metadata{});   // A: 3
	while(context.handle_events()) {}
	REQUIRE(context.compare_record_storages(sequence_number{3}));

	// replica B: the same records in a different local order, one missing, plus one of
	// its own (as if replicated s2s while the client was away)
	test::test_sync_server b(chain_sync_config{sync_mode::require_special_seen}, "test_sync_server_b.db");
	auto recs = context.server.sync.get_records(sequence_number{1}, sequence_number{3});
	REQUIRE(recs.size() == 3);
	REQUIRE(b.sync.commit_foreign(recs[0]));
	REQUIRE(b.sync.commit_foreign(recs[2]));

	// another client committing directly on B; a real record so the hopping client can
	// verify it (the block creator makes records without usable encryption)
	encryption_key const key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")};
	data_change_record_creator other(key, chain_block_id{sequence_number{2}, recs[2].hash()},
		std::nullopt, {}, recs[0].tag());
	other.add_change(create_object_id(), {}, metadata{});
	auto extra = chain_block{other.result()};
	REQUIRE(b.sync.commit_block(extra));

	// the client hops from A to B
	context.disconnect_client(0);
	while(context.handle_events()) {}
	context.client(0).io.connect(b);
	while(context.handle_events()) {}

	auto& recs0 = context.client(0).io.records();
	// converged under B's cursor: the missing record was recommitted with its tag intact
	CHECK(b.sync.current_sequence_number() == sequence_number{4});
	CHECK(recs0.last_block().sequence == sequence_number{4});
	CHECK(recs0.cursor_owner() == b.id.data());
	REQUIRE(b.sync.records().find_tag(recs[1].tag()));
	REQUIRE(recs0.find_tag(recs[1].tag()));
	CHECK(recs0.find_tag(recs[1].tag())->state() == record_state::in_sync);
	CHECK(recs0.find_tag(extra.tag()));

	// committing more on B works (the object chain survived the switch)
	context.client(0).engine.sync_object_change(oid, metadata{});                  // B: 5
	while(context.handle_events()) {}
	CHECK(b.sync.current_sequence_number() == sequence_number{5});

	// A catches up s2s (simulated); the client hops back and resyncs onto A's cursor
	for(auto const& r : b.sync.get_records(sequence_number{1}, sequence_number{5})) {
		std::ignore = context.server.sync.commit_foreign(r);
	}
	REQUIRE(context.server.sync.current_sequence_number() == sequence_number{5});
	context.disconnect_client(0);
	while(context.handle_events()) {}
	context.connect_client(0);
	while(context.handle_events()) {}

	CHECK(recs0.cursor_owner() == context.server.id.data());
	CHECK(context.compare_record_storages(sequence_number{5}));
}

// (23) colliding encryption keys (plan 4.6/D9): concurrent key rotations leave two keys
// under one sequence; records encrypted with either of them stay readable
TEST_CASE("engine sync colliding encryption keys", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	context.add_client();
	context.create_initial_record();
	while(context.handle_events()) {}

	// two rotations collided on sequence 2 (as merged from another replica)
	encryption_key const key_a{sequence_number{2}, to_octet_vector("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")};
	encryption_key const key_b{sequence_number{2}, to_octet_vector("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")};
	context.client(0).enc_keys.insert(key_a, securepath::test::random_octet_vector(16));
	context.client(0).enc_keys.insert(key_b, securepath::test::random_octet_vector(16));

	// records committed under each of the colliding keys
	auto make_change = [&](encryption_key const& key) {
		data_change_record_creator creator(key, context.server.sync.records().last_block(), std::nullopt);
		creator.add_change(create_object_id(), {}, metadata{});
		return chain_block{creator.result()};
	};
	REQUIRE(context.server.sync.commit_block(make_change(key_a)));
	REQUIRE(context.server.sync.commit_block(make_change(key_b)));
	while(context.handle_events()) {}

	// the client verified and applied both
	auto& recs = context.client(0).io.records();
	CHECK(recs.last_block().sequence == sequence_number{3});
	CHECK(recs.find(sequence_number{2}));
	CHECK(recs.find(sequence_number{3}));
}

}
