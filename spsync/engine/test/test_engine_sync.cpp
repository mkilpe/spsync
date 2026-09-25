// SPDX-License-Identifier: MIT

#include <spsync/test/test_sync_server.hpp>
#include <spsync/test/test_block_creator.hpp>

#include <spsync/client/record_util.hpp>
#include <spsync/core/data/source_record_data.hpp>
#include <spsync/engine/record_creator.hpp>
#include <spsync/protocol/error.hpp>
#include <spsync/engine/record_verifier.hpp>

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <spsync/test/test_record_data.hpp>

#include <securepath/test_frame/test_suite.hpp>

#include <atomic>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <map>

namespace securepath::sync {
using namespace securepath::sync::util;

namespace {

/// engine output observer counting object conflicts (events arrive on the loop thread)
struct rejection_observer : engine_output {
	using engine_output::engine_output;
	~rejection_observer() { stop_handler(); }

	void on_record_rejected(record_handle rec, error err) override {
		last = rec;
		last_error = err;
		++rejections;
	}

	std::atomic<int> rejections{0};
	record_handle last;
	error last_error;
};

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

using test::read_all;

/// object changes from client 0, each drained
void change_each(test::test_sync_context& context, std::vector<object_id> const& oids) {
	for(auto const& oid : oids) {
		context.client(0).engine.sync_object_change(oid, metadata{});
		while(context.handle_events()) {}
	}
}

/// a change with record data from the client, drained
record_handle change_with_data(test::test_sync_context& context, int client, octet_vector const& content) {
	auto h = context.client(client).engine.sync_object_change(create_object_id(), metadata{}, std::make_shared<memory_record_data>(content));
	while(context.handle_events()) {}
	return h;
}

/// a segment sealed by client 0, drained
record_handle seal_segment(test::test_sync_context& context) {
	auto seg = context.client(0).engine.sync_segment_end(metadata{});
	while(context.handle_events()) {}
	return seg;
}

/// the data descriptor the record's first change carries
std::optional<data_descriptor> descriptor_of(record_handle const& h) {
	return h->record().deserialise_to<data_change_record>().begin()->data.data;
}

/// the client's view of the data a record names
auto data_of(test::test_sync_context& context, int client, record_handle const& h) {
	auto& io = context.client(client).io;
	return context.client(client).engine.object_data(io.records().find_tag(h->tag()));
}

/// the loser's data: still the same, referenced once, uploaded after the rebased commit
void check_rebased_data_kept(test::test_sync_context& context, record_handle const& h1
	, data_descriptor const& descriptor1, octet_vector const& content1) {
	auto& io1 = context.client(1).io;
	auto const row1 = io1.data()->find(descriptor1.manifest_digest);
	REQUIRE(row1);
	CHECK(row1->state == record_data_state::in_sync);
	CHECK(row1->have.complete());
	CHECK(io1.records().data_reference_count(row1->local_id) == 1);
	CHECK(io1.upload_requests() == std::vector<data_id>{descriptor1.manifest_digest});

	auto own = context.client(1).engine.object_data(h1);
	REQUIRE(own);
	octet_vector read_back(content1.size());
	CHECK(own->read(0, read_back.data(), read_back.size()) == content1.size());
	CHECK(read_back == content1);
}

/// the winner's data as client 1 sees it: known, deferred, nothing of it held
void check_winner_data_deferred(test::test_sync_context& context, record_handle const& h0, octet_vector const& content0) {
	auto const descriptor0 = descriptor_of(h0);
	REQUIRE(descriptor0);
	auto remote = data_of(context, 1, h0);
	REQUIRE(remote);
	CHECK(remote->state() == record_data_state::deferred);
	CHECK(remote->size() == content0.size());
	CHECK(remote->available_size() == 0);
	CHECK(context.client(0).io.upload_requests() == std::vector<data_id>{descriptor0->manifest_digest});
}

/// the server's index of the data its chain names: these and nothing else
void check_server_index(test::test_sync_context& context, std::vector<data_id> const& ids) {
	data_state_table server_index{context.server.database};
	for(auto const& id : ids) {
		CHECK(server_index.find(id));
	}
	CHECK(server_index.all_ids().size() == ids.size());
}

/// a pending record of client 1 over every object, made off-line: its handle and the
/// tags of the objects it builds on
struct multi_change {
	record_handle handle;
	std::vector<record_tag> previous;
};

multi_change pending_multi_change(test::test_sync_context& context, std::vector<object_id> const& oids) {
	auto& client = context.client(1);
	auto& storage1 = client.io.records();
	multi_change ret;
	data_change_record_creator creator(client.enc_keys.current_key(), storage1.last_block());
	for(auto const& oid : oids) {
		ret.previous.push_back(storage1.find_last(oid)->tag());
		creator.add_change(oid, ret.previous.back(), metadata{});
	}
	ret.handle = storage1.create(creator.result());
	return ret;
}

/// the previous tag of every object as the committed record of the tag names it
std::map<object_id, record_tag> previous_tags(test::test_sync_context& context, record_tag const& tag) {
	auto committed = context.server.sync.records().find_tag(tag);
	REQUIRE(committed);
	auto rec = committed->record().deserialise_to<data_change_record>();
	std::map<object_id, record_tag> previous;
	for(auto const& c : rec) {
		previous[c.data.id] = c.data.previous_oid_record_tag;
	}
	return previous;
}

/// the segment at `end` covers [start, end] with the server's tags in order, linked to
/// the previous segment by its tag
void check_segment(test::test_sync_context& context, record_handle const& h, std::uint64_t start, std::uint64_t end
	, record_tag const& previous) {
	auto seg = h->record().deserialise_to<segment_record>();
	CHECK(h->block_id().sequence == sequence_number{end});
	CHECK(seg.data().segment_start() == sequence_number{start});
	CHECK(seg.data().segment_end() == sequence_number{end});
	CHECK(seg.data().previous_segment_tag() == previous);
	REQUIRE(seg.data().tags().size() == end - start);
	for(std::uint64_t i = 0; i != end - start; ++i) {
		CHECK(seg.data().tags()[i] == context.server.sync.records().find(sequence_number{start + i})->tag());
	}
}

/// a new client joins with the anchor hash and the keys from the invite (the root
/// record that used to carry the enveloped keys is gone)
test::test_sync_server_client_context& join_from_anchor(test::test_sync_context& context, chain_block_id const& anchor) {
	context.add_client(false, 1);
	auto& fresh = context.client(1);
	auto cfg = fresh.engine_config;
	cfg.trusted_anchor = anchor;
	fresh.engine.set_config(cfg);
	fresh.enc_keys.insert(encryption_key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")});
	context.connect_client(1);
	while(context.handle_events()) {}
	return fresh;
}

/// verification from the anchor: one segment, the records after it, nothing covered
void check_fast_verification(test::test_sync_server_client_context& client, std::size_t verified_records) {
	auto fast = client.engine.verify_history();
	REQUIRE(fast);
	CHECK(fast.value().verified_segments == 1);
	CHECK(fast.value().verified_records == verified_records);
	CHECK(fast.value().covered_records == 0);
}

/// replica B: the same records in a different local order, one missing, plus one of
/// its own (as if replicated s2s while the client was away) - a real record so the
/// hopping client can verify it (the block creator makes records without usable encryption)
chain_block fill_replica(test::test_sync_server& b, std::deque<chain_block> const& recs) {
	REQUIRE(b.sync.commit_foreign(recs[0]));
	REQUIRE(b.sync.commit_foreign(recs[2]));
	encryption_key const key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")};
	data_change_record_creator other(key, chain_block_id{sequence_number{2}, recs[2].hash()},
		std::nullopt, {}, recs[0].tag());
	other.add_change(create_object_id(), {}, metadata{});
	auto extra = chain_block{other.result()};
	REQUIRE(b.sync.commit_block(extra));
	return extra;
}

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


// (10d) a pending record the server refuses for good (its limits were not known in
// advance) is dropped and reported once; a transient rejection keeps it pending
TEST_CASE("engine sync drops a permanently rejected record", "[unit]") {
	chain_sync_config config{sync_mode::allow_all};
	config.max_record_size = 4096;   // the server enforces, the client was never told
	test::test_sync_context context(config);
	context.add_client(true, 1);
	context.create_initial_record();
	while(context.handle_events()) {}

	rejection_observer observer{context.client(0).single_thread_event_loop};
	context.client(0).engine.set_output(&observer);

	metadata big;
	big.insert("blob", octet_vector(8000, 1));
	auto h = context.client(0).engine.sync_object_change(util::create_object_id(), big);
	while(context.handle_events()) {}
	CHECK(h->state() == record_state::invalid);
	CHECK(observer.rejections == 1);
	CHECK(observer.last_error.code() == make_error_code(protocol::errc::record_too_big));
	CHECK(!context.client(0).io.records().find_first_pending_commit());

	// a record that fits goes through as before
	context.client(0).engine.sync_object_change(util::create_object_id(), metadata{});
	while(context.handle_events()) {}
	CHECK(context.server.sync.current_sequence_number() == sequence_number{2});
	context.client(0).engine.set_output(nullptr);
}

// (10c, RDS 8) the engine refuses a change that exceeds the storage's record limit before
// committing, once the server reported the limits with the sequence answer
TEST_CASE("engine sync refuses oversized records", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::allow_all});
	context.server.limits = storage_limits{4096, default_chunk_size};
	context.add_client(true, 1);
	context.create_initial_record();
	while(context.handle_events()) {}

	metadata big;
	big.insert("blob", octet_vector(8000, 1));
	bool refused = false;
	try {
		context.client(0).engine.sync_object_change(util::create_object_id(), big);
	} catch(error const& err) {
		refused = err.code() == make_error_code(errc::record_too_big);
	}
	CHECK(refused);

	// a small change goes through as before
	context.client(0).engine.sync_object_change(util::create_object_id(), metadata{});
	while(context.handle_events()) {}
	CHECK(context.server.sync.current_sequence_number() == sequence_number{2});

	// the limits were learned once and persisted: an offline change is refused as well
	CHECK(context.client(0).io.records().limits() == storage_limits{4096, default_chunk_size});
	context.disconnect_client(0);
	context.handle_events();
	refused = false;
	try {
		context.client(0).engine.sync_object_change(util::create_object_id(), big);
	} catch(error const& err) {
		refused = err.code() == make_error_code(errc::record_too_big);
	}
	CHECK(refused);
}

// (10b) a client that joins an existing storage and commits before its first records
// arrived (the cli sends a message right after joining): the record references no
// special record yet, the server rejects it as out of sync and the engine rebases it
// onto the membership record once that is in sync - without a retry storm
TEST_CASE("engine sync commit before first sync", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_special_seen});
	context.add_client(true, 1);
	context.add_client(false, 1);
	context.create_initial_record();
	context.client(0).engine.sync_object_change(util::create_object_id(), metadata{});
	while(context.handle_events()) {}
	REQUIRE(context.server.sync.current_sequence_number() == sequence_number{2});

	// the real network pushes the newest record ahead of the fetch: the data record
	// arrives first and waits (its special reference is unknown), and the client's own
	// record gets based on it without any special reference
	context.connect_client(1);
	auto pushed = context.server.sync.get_records(sequence_number{2}, sequence_number{2});
	REQUIRE(pushed.size() == 1);
	context.client(1).engine.on_record_received(pushed[0], {});
	auto h = context.client(1).engine.sync_object_change(util::create_object_id(), metadata{});
	auto const requests_before = context.client(1).io.request_count();
	while(context.handle_events()) {}

	CHECK(h->state() == record_state::in_sync);
	CHECK(context.server.sync.current_sequence_number() == sequence_number{3});
	CHECK(context.compare_record_storages(sequence_number{3}));
	// a handful of requests: sequence, fetch, the rejected commit and the rebased one
	CHECK(context.client(1).io.request_count() - requests_before < 10);
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

// (RDS 3) a change with record data that loses the race is rebased with its data: the
// descriptor halves move into the rebuilt record, the data keeps its id, its reference
// and its chunks, and is uploaded once the rebased record is confirmed. The other
// client sees both datas as deferred; the server indexes what its chain names
TEST_CASE("engine sync rebases a change with record data", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client(true, 2);
	context.create_initial_record();
	while(context.handle_events()) {}

	auto oid = create_object_id();
	context.client(0).engine.sync_object_change(oid, metadata{});
	while(context.handle_events()) {}

	auto const content0 = securepath::test::random_octet_vector(3000);
	auto const content1 = securepath::test::random_octet_vector(70000);
	auto h0 = context.client(0).engine.sync_object_change(oid, metadata{}, std::make_shared<memory_record_data>(content0));
	auto h1 = context.client(1).engine.sync_object_change(oid, metadata{}, std::make_shared<memory_record_data>(content1));
	auto const original_tag = h1->tag();
	auto const descriptor1 = descriptor_of(h1);
	REQUIRE(descriptor1);
	while(context.handle_events()) {}

	CHECK(context.compare_record_storages(sequence_number{4}));
	CHECK(h1->tag() != original_tag);
	CHECK(h1->state() == record_state::in_sync);
	CHECK(descriptor_of(h1) == descriptor1);

	check_rebased_data_kept(context, h1, *descriptor1, content1);
	check_winner_data_deferred(context, h0, content0);
	check_server_index(context, {descriptor_of(h0)->manifest_digest, descriptor1->manifest_digest});
}

// (RDS 6) record data from one member to another through the engines: the author's data
// is uploaded when its record is confirmed, the other member fetches it on demand (lazy)
// or as soon as the record arrives (auto fetch up to a size), and reads the plaintext
TEST_CASE("engine sync transfers record data", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client(true, 3);
	context.create_initial_record();
	while(context.handle_events()) {}

	// client 2 fetches small data unasked
	auto eager = context.client(2).engine_config;
	eager.auto_fetch_max_size = 1024 * 1024;
	context.client(2).engine.set_config(eager);

	auto const small = securepath::test::random_octet_vector(70000);
	auto const big = securepath::test::random_octet_vector(2 * 1024 * 1024 + 5000);
	auto h_small = change_with_data(context, 0, small);
	auto h_big = change_with_data(context, 0, big);
	CHECK(context.compare_record_storages(sequence_number{3}));

	// lazy: client 1 knows both datas and holds neither
	CHECK(context.client(1).io.fetch_requests().empty());
	REQUIRE(data_of(context, 1, h_small));
	CHECK(data_of(context, 1, h_small)->state() == record_data_state::deferred);
	CHECK(data_of(context, 1, h_big)->state() == record_data_state::deferred);

	// auto fetch: client 2 has the small one already - asked for when the record came, and
	// again after the notification when that was before the author's upload had landed
	CHECK(!context.client(2).io.fetch_requests().empty());
	CHECK(context.client(2).io.fetch_requests().size() <= 2);
	REQUIRE(data_of(context, 2, h_small)->state() == record_data_state::in_sync);
	CHECK(read_all(*data_of(context, 2, h_small)) == small);
	CHECK(data_of(context, 2, h_big)->state() == record_data_state::deferred);

	// asked for
	auto& io1 = context.client(1).io;
	auto fetched = context.client(1).engine.fetch_object_data(io1.records().find_tag(h_big->tag()));
	REQUIRE(fetched);
	CHECK(fetched->state() == record_data_state::download_pending);
	while(context.handle_events()) {}
	CHECK(fetched->state() == record_data_state::in_sync);
	CHECK(read_all(*fetched) == big);
	CHECK(io1.fetch_requests().size() == 1);
	CHECK(data_of(context, 1, h_small)->state() == record_data_state::deferred);

	// the author never fetches its own
	CHECK(context.client(0).io.fetch_requests().empty());
	CHECK(read_all(*data_of(context, 0, h_big)) == big);
}

// (13b) the same client changes an object twice before the first change is confirmed:
// in strict mode the second is stacked on the first, so once the first lands its last
// seen block is the head and only its previous object tag is stale. The rebase must not
// be skipped by the "already up to date" check: the server refuses the stale tag and
// the record would stall
TEST_CASE("engine sync rebases a stacked object change", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client(true, 1);
	context.create_initial_record();
	while(context.handle_events()) {}

	auto oid = create_object_id();
	context.client(0).engine.sync_object_change(oid, metadata{});
	while(context.handle_events()) {}

	conflict_observer observer{context.client(0).single_thread_event_loop};
	context.client(0).engine.set_output(&observer);

	auto h1 = context.client(0).engine.sync_object_change(oid, metadata{});
	auto h2 = context.client(0).engine.sync_object_change(oid, metadata{});
	auto original_tag = h2->tag();
	while(context.handle_events()) {}

	CHECK(context.compare_record_storages(sequence_number{4}));
	CHECK(h1->state() == record_state::in_sync);
	CHECK(h2->state() == record_state::in_sync);
	CHECK(h2->tag() != original_tag);
	CHECK(context.server.sync.records().find_tag(h2->tag()));
	WAIT_CHECK(observer.conflicts == 1, 2s);
	context.client(0).engine.set_output(nullptr);
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

	// objects a, b and c
	std::vector<object_id> const oids{create_object_id(), create_object_id(), create_object_id()};
	for(auto const& oid : oids) {
		context.client(0).engine.sync_object_change(oid, metadata{});
	}
	while(context.handle_events()) {}
	CHECK(context.compare_record_storages(sequence_number{4}));

	// client 1 goes off-line holding a pending multi change record over a, b and c
	context.disconnect_client(1);
	auto const pending = pending_multi_change(context, oids);
	auto const& h = pending.handle;
	auto original_tag = h->tag();

	// meanwhile b and c move underneath it
	context.client(0).engine.sync_object_change(oids[1], metadata{});
	context.client(0).engine.sync_object_change(oids[2], metadata{});
	while(context.handle_events()) {}
	auto new_tag_b = context.client(0).io.records().find_last(oids[1])->tag();
	auto new_tag_c = context.client(0).io.records().find_last(oids[2])->tag();

	conflict_observer observer{context.client(1).single_thread_event_loop};
	context.client(1).engine.set_output(&observer);

	context.connect_client(1);
	while(context.handle_events()) {}

	CHECK(context.compare_record_storages(sequence_number{7}));
	CHECK(h->tag() != original_tag);

	// the rebuilt record keeps the non-conflicting change and rebases the conflicting ones
	auto const previous = previous_tags(context, h->tag());
	REQUIRE(previous.size() == 3);
	CHECK(previous.at(oids[0]) == pending.previous[0]);
	CHECK(previous.at(oids[1]) == new_tag_b);
	CHECK(previous.at(oids[2]) == new_tag_c);

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

	check_segment(context, h, 1, 4, record_tag{});

	// the encrypted header carries the metadata and the record verifies
	auto seg = h->record().deserialise_to<segment_record>();
	segment_record_verifier ver(context.client(0).enc_keys.current_key(), seg, h->record().auth());
	CHECK(ver.is_authentic());
	CHECK(ver.header().metadata().find<std::string>("checkpoint") == std::string{"test"});

	// the next segment starts where the first ended and links it by tag (the backbone)
	change_each(context, {create_object_id()});
	auto h2 = seal_segment(context);
	CHECK(context.compare_record_storages(sequence_number{6}));
	check_segment(context, h2, 4, 6, h->tag());
	CHECK(h2->record().deserialise_to<segment_record>().data().tags()[0] == h->tag());
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
	change_each(context, {oid, create_object_id(), oid});                        // 2: add A, 3: add B, 4: change A
	auto seg = seal_segment(context);                                            // 5: covers [1,5)
	change_each(context, {create_object_id()});                                  // 6
	REQUIRE(context.compare_record_storages(sequence_number{6}));

	// the server cuts before the segment: the root user change goes, the object chains stay
	auto removed = context.server.sync.log().cut_before(seg->tag());
	REQUIRE(removed.size() == 1);
	CHECK(removed[0].sequence() == sequence_number{1});

	auto& fresh = join_from_anchor(context, seg->block_id());

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
	check_fast_verification(fresh, 4);
	auto cfg = fresh.engine_config;
	cfg.trusted_anchor = seg->block_id();
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
	change_each(context, {oid, oid});                                            // 2: add A, 3: change A
	auto seg = seal_segment(context);                                            // 4: covers [1,4)
	change_each(context, {create_object_id()});                                  // 5
	REQUIRE(context.compare_record_storages(sequence_number{5}));

	CHECK_THROWS(context.client(0).engine.prune_history(securepath::test::random_octet_vector(16)));

	// client 0 prunes at the newest segment; the server and client 1 keep everything
	auto anchor = context.client(0).engine.prune_history();
	CHECK(anchor == seg->block_id());

	auto& recs = context.client(0).io.records();
	CHECK(!recs.find(sequence_number{1}));
	CHECK(recs.find(sequence_number{2}));
	CHECK(recs.find(sequence_number{3}));
	CHECK(recs.find(sequence_number{4}));
	CHECK(recs.find(sequence_number{5}));
	CHECK(context.server.sync.records().find(sequence_number{1}));

	// verification works from the anchor right away...
	check_fast_verification(context.client(0), 3);
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
	change_each(context, {oid, create_object_id()});                             // A: 2, A: 3
	REQUIRE(context.compare_record_storages(sequence_number{3}));

	// replica B with another client's record committed directly on it
	test::test_sync_server b(chain_sync_config{sync_mode::require_special_seen}, "test_sync_server_b.db");
	auto recs = context.server.sync.get_records(sequence_number{1}, sequence_number{3});
	REQUIRE(recs.size() == 3);
	auto const extra = fill_replica(b, recs);

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


namespace {

struct anchor_observer : engine_output {
	using engine_output::engine_output;
	~anchor_observer() { stop_handler(); }

	void on_anchor_mismatch(chain_block served) override {
		served_seq = served.sequence();
		++mismatches;
	}

	std::atomic<int> mismatches{0};
	sequence_number served_seq;
};

/// a fresh client joining with the anchor from its invitation and the key it carried
test::test_sync_server_client_context& join_with_anchor(test::test_sync_context& context, int n, chain_block_id const& anchor
	, anchor_observer& observer) {
	context.add_client(false, 1);
	auto& fresh = context.client(n);
	auto cfg = fresh.engine_config;
	cfg.trusted_anchor = anchor;
	fresh.engine.set_config(cfg);
	fresh.engine.set_output(&observer);
	fresh.enc_keys.insert(encryption_key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")});
	context.connect_client(n);
	while(context.handle_events()) {}
	return fresh;
}

/// the first record's id as the inviter reads it off its records
chain_block_id root_of(test::test_sync_context& context) {
	auto root = context.server.sync.records().find(sequence_number{1});
	REQUIRE(root);
	return root->block_id();
}

/// a storage of three records; a joiner with the right root anchor syncs all of them, one
/// with another hash at sequence 1 gets nothing, hears why and cannot commit
void check_root_anchoring(sync_mode mode) {
	test::test_sync_context context(chain_sync_config{mode});
	context.add_client(true, 1);
	context.create_initial_record();
	change_each(context, {create_object_id(), create_object_id()});               // 2, 3
	while(context.handle_events()) {}
	auto const root = root_of(context);

	anchor_observer trusting{context.client(0).single_thread_event_loop};
	auto& joiner = join_with_anchor(context, 1, root, trusting);
	CHECK(context.compare_record_storages(sequence_number{3}));
	CHECK(trusting.mismatches == 0);
	joiner.engine.set_output(nullptr);

	// the server shows a history that does not start with the invited block
	anchor_observer deceived{context.client(0).single_thread_event_loop};
	auto& victim = join_with_anchor(context, 2, chain_block_id{sequence_number{1}, securepath::test::random_octet_vector(64)}, deceived);
	WAIT_CHECK(deceived.mismatches == 1, 2s);
	CHECK(deceived.served_seq == sequence_number{1});
	auto const& recs = victim.io.records();
	CHECK(!recs.find(sequence_number{1}));
	CHECK(!recs.find(sequence_number{2}));
	CHECK(!recs.find(sequence_number{3}));
	CHECK(recs.find(sequence_number{1}, record_state::invalid));
	CHECK(!recs.find_last());
	CHECK(context.server.sync.current_sequence_number() == sequence_number{3});
	victim.engine.set_output(nullptr);
}

}

// (plan 5.5) root anchoring: the invitation names the first block, the chain must start
// with it - in strict and in weak modes
TEST_CASE("engine sync root anchor from the invitation", "[unit]") {
	SECTION("strict") {
		check_root_anchoring(sync_mode::require_all_seen);
	}
	SECTION("weak") {
		check_root_anchoring(sync_mode::allow_all);
	}
}

// (plan 5.5) with an anchor above the first record (a joiner after a history cut) nothing
// enters in sync before the anchor: a root record served first waits, promoted when the
// anchor lands, and the tail chains from the anchor
TEST_CASE("engine sync nothing before the anchor", "[unit]") {
	test::test_sync_context context(chain_sync_config{sync_mode::require_all_seen});
	context.add_client(true, 1);
	context.create_initial_record();
	change_each(context, {create_object_id()});                                    // 2
	auto seg = seal_segment(context);                                              // 3
	change_each(context, {create_object_id()});                                    // 4
	while(context.handle_events()) {}

	// the joiner anchors on the segment while the server still serves the whole history
	anchor_observer observer{context.client(0).single_thread_event_loop};
	auto& joiner = join_with_anchor(context, 1, seg->block_id(), observer);
	CHECK(observer.mismatches == 0);
	auto const& recs = joiner.io.records();
	CHECK(recs.find(sequence_number{3}));
	CHECK(recs.find(sequence_number{4}));
	// the records below the anchor were promoted when it landed
	CHECK(recs.find(sequence_number{1}));
	CHECK(recs.find(sequence_number{2}));
	CHECK(context.compare_record_storages(sequence_number{4}));
	joiner.engine.set_output(nullptr);
}

}
