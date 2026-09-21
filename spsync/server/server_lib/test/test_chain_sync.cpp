#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <spsync/protocol/error.hpp>
#include <spsync/server/server_lib/chain_sync.hpp>

#include <spsync/test/test_block_creator.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>

// + (1) basic test for committing with 'all seen' mode
// + (2) basic test for committing with 'allow all' mode
// + (3) basic test for committing with 'require special' mode
// + (4) basic test for committing with 'require object add/remove' mode

namespace securepath::sync {

using test::test_block_creator;
std::string const db_name = "record_storage_test.db";

static void remove_database_test_db() {
	std::remove(db_name.c_str());
}

// (1) basic test for committing with 'all seen' mode
TEST_CASE("chain_sync require all config", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_all_seen});

	test_block_creator creator;
	auto rec = creator.test_user_change();

	// commit first block
	CHECK(sync.commit_block(rec));
	CHECK(check_result_error(sync.commit_block(rec), protocol::errc::record_already_committed));

	auto creator_copy{creator};
	CHECK(sync.commit_block(creator.test_user_change()));
	CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));

	auto dchange = creator.test_data_change();
	CHECK(sync.commit_block(dchange));
	CHECK(sync.commit_block(creator.test_followup_data_change(dchange)));

	CHECK(sync.current_sequence_number() == creator.last_server_seq);

	{
		auto creator_copy{creator};
		// using same previous oid record tag, which should error out
		CHECK(check_result_error(sync.commit_block(creator_copy.test_followup_data_change(dchange)), protocol::errc::record_out_of_sync));
	}
	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_data_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_data_change()), protocol::errc::record_out_of_sync));
	}

	CHECK(sync.current_sequence_number() == creator.last_server_seq);
	CHECK(sync.get_records(sequence_number{1}, creator.last_server_seq+1).size() == creator.last_server_seq.value);
	CHECK(sync.get_records(sequence_number{1}, sequence_number{100}).size() == creator.last_server_seq.value);
}

// (2) basic test for committing with 'allow all' mode
TEST_CASE("chain_sync allow all config", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::allow_all});

	test_block_creator creator;
	auto rec = creator.test_user_change();

	// commit first block
	CHECK(sync.commit_block(rec));
	CHECK(check_result_error(sync.commit_block(rec), protocol::errc::record_already_committed));

	auto creator_copy{creator};
	CHECK(sync.commit_block(creator.test_user_change()));
	CHECK(sync.commit_block(creator_copy.test_user_change()));

	auto dchange = creator.test_data_change();
	CHECK(sync.commit_block(dchange));
	CHECK(sync.commit_block(creator.test_followup_data_change(dchange)));

	// using same previous oid record tag, which should error out
	CHECK(check_result_error(sync.commit_block(creator.test_followup_data_change(dchange)), protocol::errc::record_out_of_sync));

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_data_change()));
		CHECK(sync.commit_block(creator_copy.test_data_change()));
	}
}

// (3) basic test for committing with 'require special' mode
TEST_CASE("chain_sync require special config", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});

	test_block_creator creator;
	auto rec = creator.test_user_change();

	// commit first block
	CHECK(sync.commit_block(rec));
	CHECK(check_result_error(sync.commit_block(rec), protocol::errc::record_already_committed));

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));
	}

	auto dchange = creator.test_data_change();
	CHECK(sync.commit_block(dchange));
	CHECK(sync.commit_block(creator.test_followup_data_change(dchange)));

	// using same previous oid record tag, which should error out
	CHECK(check_result_error(sync.commit_block(creator.test_followup_data_change(dchange)), protocol::errc::record_out_of_sync));

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_data_change()));
		CHECK(sync.commit_block(creator_copy.test_data_change()));
	}
	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));
	}
}

// (4) basic test for committing with 'require object add/remove' mode
TEST_CASE("chain_sync require data add remove config", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_data_add_remove_seen});

	test_block_creator creator;
	auto rec = creator.test_user_change();

	// commit first block
	CHECK(sync.commit_block(rec));
	CHECK(check_result_error(sync.commit_block(rec), protocol::errc::record_already_committed));

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));
	}

	auto dchange = creator.test_data_change();
	CHECK(sync.commit_block(dchange));
	CHECK(sync.commit_block(creator.test_followup_data_change(dchange)));

	{
		auto creator_copy{creator};
		// using same previous oid record tag, which should error out
		CHECK(check_result_error(sync.commit_block(creator_copy.test_followup_data_change(dchange)), protocol::errc::record_out_of_sync));
	}

	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_data_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_data_change()), protocol::errc::record_out_of_sync));
	}

	auto change1 = creator.test_data_change();
	CHECK(sync.commit_block(change1));
	auto change2 = creator.test_data_change();
	CHECK(sync.commit_block(change2));
	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_followup_data_change(change1)));
		CHECK(sync.commit_block(creator_copy.test_followup_data_change(change2)));
	}
	{
		auto creator_copy{creator};
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(check_result_error(sync.commit_block(creator_copy.test_user_change()), protocol::errc::record_out_of_sync));
	}
}



// (5) mode cursors are replayed from the database on reopen (defect B1)
TEST_CASE("chain_sync special cursor replay on reopen", "[unit]") {
	remove_database_test_db();
	test_block_creator creator;
	test_block_creator stale;
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});
		CHECK(sync.commit_block(creator.test_user_change()));
		stale = creator; // has seen only the first special record
		CHECK(sync.commit_block(creator.test_user_change()));
	}
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});
		CHECK(sync.current_sequence_number() == creator.last_server_seq);
		// a client that has not seen the newest special record must still be rejected after restart
		CHECK(check_result_error(sync.commit_block(stale.test_user_change()), protocol::errc::record_out_of_sync));
		CHECK(sync.commit_block(creator.test_data_change()));
	}
}

// (6) data add cursor is replayed from the database on reopen (defect B1)
TEST_CASE("chain_sync data add cursor replay on reopen", "[unit]") {
	remove_database_test_db();
	test_block_creator creator;
	test_block_creator stale;
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_data_add_remove_seen});
		CHECK(sync.commit_block(creator.test_user_change()));
		stale = creator; // has seen only the first record
		CHECK(sync.commit_block(creator.test_data_change()));
	}
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_data_add_remove_seen});
		// a client that has not seen the add at seq 2 must still be rejected after restart
		CHECK(check_result_error(sync.commit_block(stale.test_data_change()), protocol::errc::record_out_of_sync));
		CHECK(sync.commit_block(creator.test_data_change()));
	}
}

// (6b) truncation: head and mode cursors are re-derived after truncate_from (plan 3.1/3.2)
TEST_CASE("chain_sync truncate then recommit", "[unit]") {
	remove_database_test_db();
	test_block_creator creator;
	test_block_creator snapshot;
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});
		CHECK(sync.commit_block(creator.test_user_change()));
		snapshot = creator; // has seen only the first special record
		CHECK(sync.commit_block(creator.test_user_change()));
		CHECK(sync.commit_block(creator.test_data_change()));

		auto removed = sync.truncate_from(sequence_number{2});
		REQUIRE(removed.size() == 2);
		CHECK(removed[0].sequence() == sequence_number{2});
		CHECK(removed[1].sequence() == sequence_number{3});

		// head and mode cursors are re-derived live, no reopen needed
		CHECK(sync.current_sequence_number() == sequence_number{1});
		auto recommit = snapshot;
		CHECK(sync.commit_block(recommit.test_user_change()));
		CHECK(sync.current_sequence_number() == sequence_number{2});
	}
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});
		CHECK(sync.current_sequence_number() == sequence_number{2});
		// a client that saw only the first special record is behind the recommitted one
		creator = snapshot;
		CHECK(check_result_error(sync.commit_block(creator.test_user_change()), protocol::errc::record_out_of_sync));
	}
}

// (6c) segment coverage validation (segments plan SEG 3): range, tag list and backbone
// must match the chain, in every mode
TEST_CASE("chain_sync segment coverage validation", "[unit]") {
	auto mode = GENERATE(sync_mode::allow_all, sync_mode::require_special_seen,
		sync_mode::require_data_add_remove_seen, sync_mode::require_all_seen);
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{mode});

	test_block_creator creator;
	CHECK(sync.commit_block(creator.test_user_change()));
	CHECK(sync.commit_block(creator.test_data_change()));

	{ // wrong tag list is refused
		auto c = creator;
		std::deque<record_tag> reversed{c.created_tags.rbegin(), c.created_tags.rend()};
		CHECK(check_result_error(sync.commit_block(c.test_segment(
			plain_segment_data{sequence_number{1}, sequence_number{3}, reversed})), protocol::errc::invalid_record));
	}
	{ // wrong amount of tags is refused
		auto c = creator;
		CHECK(check_result_error(sync.commit_block(c.test_segment(
			plain_segment_data{sequence_number{1}, sequence_number{3}, {c.created_tags[0]}})), protocol::errc::invalid_record));
	}
	{ // an end that is not the segment's own sequence is refused
		auto c = creator;
		CHECK(check_result_error(sync.commit_block(c.test_segment(
			plain_segment_data{sequence_number{1}, sequence_number{2}, {c.created_tags[0]}})), protocol::errc::invalid_record));
	}
	{ // the first segment must start at 1
		auto c = creator;
		CHECK(check_result_error(sync.commit_block(c.test_segment(
			plain_segment_data{sequence_number{2}, sequence_number{3}, {c.created_tags[1]}})), protocol::errc::record_out_of_sync));
	}

	// the valid first segment covers [1, 3)
	auto s1 = creator.test_segment(plain_segment_data{sequence_number{1}, sequence_number{3}, creator.created_tags});
	CHECK(sync.commit_block(s1));

	{ // a gap to the previous segment is refused
		auto c = creator;
		CHECK(check_result_error(sync.commit_block(c.test_segment(
			plain_segment_data{sequence_number{4}, sequence_number{4}, {}, s1.tag()})), protocol::errc::record_out_of_sync));
	}
	{ // a wrong backbone tag is refused
		auto c = creator;
		CHECK(check_result_error(sync.commit_block(c.test_segment(
			plain_segment_data{sequence_number{3}, sequence_number{4}, {s1.tag()}
				, securepath::test::random_octet_vector(16)})), protocol::errc::record_out_of_sync));
	}
	{ // a missing backbone tag is refused once a segment exists
		auto c = creator;
		CHECK(check_result_error(sync.commit_block(c.test_segment(
			plain_segment_data{sequence_number{3}, sequence_number{4}, {s1.tag()}})), protocol::errc::record_out_of_sync));
	}

	// the valid second segment continues from the previous end, covering the previous segment
	CHECK(sync.commit_block(creator.test_segment(
		plain_segment_data{sequence_number{3}, sequence_number{4}, {s1.tag()}, s1.tag()})));
}

// (6d) a stale segment is an advisory checkpoint in allow_all (D9), rejected in the seen modes
TEST_CASE("chain_sync stale segment", "[unit]") {
	auto mode = GENERATE(sync_mode::allow_all, sync_mode::require_special_seen,
		sync_mode::require_data_add_remove_seen, sync_mode::require_all_seen);
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{mode});

	test_block_creator creator;
	CHECK(sync.commit_block(creator.test_user_change()));
	CHECK(sync.commit_block(creator.test_data_change()));
	auto stale = creator; // has not seen the next record
	CHECK(sync.commit_block(creator.test_data_change()));

	auto seg = stale.test_segment(plain_segment_data{sequence_number{1}, sequence_number{3}, stale.created_tags});
	auto res = sync.commit_block(seg);
	if(mode == sync_mode::allow_all) {
		// truthful coverage of the stated range is enough; the sequence is assigned past it
		REQUIRE(res);
		CHECK(res.value().sequence() == sequence_number{4});
		// the next segment continues from the STATED end, so the unseen record and the
		// stale segment both stay covered
		CHECK(sync.commit_block(creator.test_segment(
			plain_segment_data{sequence_number{3}, sequence_number{4}, {creator.created_tags[2]}, seg.tag()})));
	} else {
		CHECK(check_result_error(res, protocol::errc::record_out_of_sync));
	}
}

// (6e) history cut at a segment (segments plan SEG 5): object chains are retained, the
// anchor becomes the fetch start and the rules/cursors survive a reopen
TEST_CASE("chain_sync history cut at segment", "[unit]") {
	remove_database_test_db();
	test_block_creator creator;
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_all_seen});
		CHECK(sync.commit_block(creator.test_user_change()));
		auto add = creator.test_data_change();
		CHECK(sync.commit_block(add));
		CHECK(sync.commit_block(creator.test_followup_data_change(add)));
		auto add2 = creator.test_data_change();
		CHECK(sync.commit_block(add2));
		auto seg = creator.test_segment(plain_segment_data{sequence_number{1}, sequence_number{5}, creator.created_tags});
		CHECK(sync.commit_block(seg));

		// only a committed segment can anchor a cut
		CHECK_THROWS(sync.log().cut_before(add.tag()));
		CHECK_THROWS(sync.log().cut_before(securepath::test::random_octet_vector(16)));

		// the cut drops the root user change; both object chains are retained
		auto removed = sync.log().cut_before(seg.tag());
		REQUIRE(removed.size() == 1);
		CHECK(removed[0].sequence() == sequence_number{1});
		CHECK(sync.current_sequence_number() == sequence_number{5});

		// fetching from the start skips the cut sequence and serves the rest
		auto recs = sync.get_records(sequence_number{1}, sequence_number{5});
		REQUIRE(recs.size() == 4);
		CHECK(recs[0].sequence() == sequence_number{2});
		CHECK(recs.back().sequence() == sequence_number{5});

		// a follow-up to a retained object still validates against its chain
		CHECK(sync.commit_block(creator.test_followup_data_change(add2)));
		// and the next segment continues the backbone over the cut storage
		CHECK(sync.commit_block(creator.test_segment(
			plain_segment_data{sequence_number{5}, sequence_number{7}
				, {seg.tag(), creator.created_tags[5]}, seg.tag()})));
	}
	{
		// cursors and rules survive a reopen of the cut storage
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_all_seen});
		CHECK(sync.current_sequence_number() == sequence_number{7});
		CHECK(sync.commit_block(creator.test_data_change()));
	}
}

// (6f) the weak-mode seen rule is tag bound (plan 4.3/D4): judged by the referenced
// special tag, not by replica-local sequences
TEST_CASE("chain_sync tag bound special references", "[unit]") {
	auto mode = GENERATE(sync_mode::require_special_seen, sync_mode::require_data_add_remove_seen);
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{mode});

	test_block_creator creator;
	CHECK(sync.commit_block(creator.test_user_change()));
	auto stale = creator; // has seen only the first special record
	CHECK(sync.commit_block(creator.test_user_change()));

	// referencing the newest special by tag is accepted
	CHECK(sync.commit_block(creator.test_data_change()));

	// a stale special reference is rejected, whatever its local sequence claims
	CHECK(check_result_error(sync.commit_block(stale.test_data_change()), protocol::errc::record_out_of_sync));

	{ // an unknown special reference is rejected
		auto c = creator;
		c.last_special_tag = securepath::test::random_octet_vector(16);
		CHECK(check_result_error(sync.commit_block(c.test_data_change()), protocol::errc::record_out_of_sync));
	}
	{ // a reference to a non-special record is malformed
		auto c = creator;
		c.last_special_tag = c.created_tags.back(); // the data change
		CHECK(check_result_error(sync.commit_block(c.test_user_change()), protocol::errc::invalid_record));
	}
}

// (6g) foreign commits skip the seen rules (plan 4.3): the origin enforced them against
// its own order, re-checking here would make replicas diverge on concurrent records
TEST_CASE("chain_sync commit_foreign is lenient", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_special_seen});

	test_block_creator creator;
	CHECK(sync.commit_block(creator.test_user_change()));
	auto other = creator; // another replica's client state after the first special
	CHECK(sync.commit_block(creator.test_user_change()));

	// a concurrent special accepted by the other replica fails the local seen rule but
	// is applied through the foreign path; duplicates stay rejected
	auto foreign = other.test_user_change();
	CHECK(check_result_error(sync.commit_block(foreign), protocol::errc::record_out_of_sync));
	auto res = sync.commit_foreign(foreign);
	REQUIRE(res);
	CHECK(res.value().sequence() == sequence_number{3});
	CHECK(check_result_error(sync.commit_foreign(foreign), protocol::errc::record_already_committed));
}

// (6h) a replicated storage accepts only delta mode user changes after the first (plan 4.6/D9)
TEST_CASE("chain_sync replicated storage requires delta user changes", "[unit]") {
	remove_database_test_db();
	chain_sync_config config{sync_mode::allow_all};
	config.replication = replication_mode::weak;
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), config);

	test_block_creator creator;
	// the test creator makes delta free user changes with an empty (default) user set;
	// craft records with explicit modes
	auto make_change = [&](users_change_mode mode) {
		auth_record<user_change_record> rec{
			user_change_record{creator.next_record_base(), plain_user_change_data{users{mode}},
				encrypted_record_header<user_change_header>{}}, util::content_auth{securepath::test::random_octet_vector(16)}};
		return creator.next_block(rec);
	};

	// the initial membership of a new storage is a full change (nothing to drop yet)
	CHECK(sync.commit_block(make_change(users_change_mode::full)));
	CHECK(check_result_error(sync.commit_block(make_change(users_change_mode::full)), protocol::errc::invalid_record));
	CHECK(sync.commit_block(make_change(users_change_mode::delta)));
}

// (6i, RDS 8) the record content limit is judged the same way after a reopen and on the
// foreign path, and a range of large records is fetched in size aware batches instead of
// wedging on the transport frame cap
TEST_CASE("chain_sync record size limit and size aware batching", "[unit]") {
	remove_database_test_db();
	chain_sync_config config{sync_mode::allow_all};
	config.max_record_size = 4096;
	config.max_response_bytes = 64 * 1024;

	test_block_creator creator;
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), config);
		REQUIRE(sync.commit_block(creator.test_user_change()));
		auto big = creator.test_multi_data_change(400);
		REQUIRE(big.record_bytes().size() > 4096);
		CHECK(check_result_error(sync.commit_block(big), protocol::errc::record_too_big));
		CHECK(check_result_error(sync.commit_foreign(big), protocol::errc::record_too_big));
		for(int i = 0; i != 40; ++i) {
			REQUIRE(sync.commit_block(creator.test_multi_data_change(100)));
		}
		REQUIRE(sync.current_sequence_number() == sequence_number{41});
	}
	{
		chain_sync sync(database::sqlite::create_sqlite_connection(db_name), config);
		CHECK(check_result_error(sync.commit_block(creator.test_multi_data_change(400)), protocol::errc::record_too_big));

		// ~3 KB of content plus the per record allowance: a 64 KiB batch holds a few, never 30
		auto batch = sync.get_records(sequence_number{1}, sequence_number{41});
		REQUIRE(!batch.empty());
		CHECK(batch.size() < 30);
		CHECK(sync.get_envelopes(sequence_number{1}, sequence_number{41}).size() == batch.size());

		// walking the ranges the way clients and peers do fetches everything
		std::size_t total = 0;
		sequence_number next{1};
		while(next <= sequence_number{41}) {
			auto b = sync.get_records(next, sequence_number{41});
			REQUIRE(!b.empty());
			total += b.size();
			next = b.back().sequence() + 1;
		}
		CHECK(total == 41);
	}
}

// (6j) a client continues a fetch FROM the last record it holds, so the first record of
// its range is one it has: a batch must get past it whatever the sizes are, or the same
// answer comes again for ever (found 2026-09-21 when the batch budget went to 1 MiB)
TEST_CASE("chain_sync batches get past the record a fetch continues from", "[unit]") {
	remove_database_test_db();
	chain_sync_config config{sync_mode::allow_all};
	config.max_record_size = max_record_size_range.highest;
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), config);
	REQUIRE(config.max_response_bytes == 1024 * 1024);

	test_block_creator creator;
	REQUIRE(sync.commit_block(creator.test_user_change()));
	// each pair of neighbours is more than the budget
	std::vector<std::size_t> const sizes{300 * 1024, 1200 * 1024, 900 * 1024, 2000 * 1024, 700 * 1024, 100, 100, 1900 * 1024};
	for(auto size : sizes) {
		REQUIRE(sync.commit_block(creator.test_big_data_change(size)));
	}
	auto const last = sync.current_sequence_number();
	REQUIRE(last == sequence_number{1 + sizes.size()});

	// the way the engine walks: from the record held, until the head
	sequence_number held{1};
	std::size_t requests = 0;
	while(held < last && requests != 50) {
		auto const batch = sync.get_records(held, sequence_number{});
		++requests;
		REQUIRE(!batch.empty());
		CHECK(batch.front().sequence() == held);
		// past the record the fetch continued from
		REQUIRE(batch.back().sequence() > held);
		// two records, or what fits the budget
		std::size_t bytes = 0;
		for(auto const& b : batch) {
			bytes += b.record_bytes().size();
		}
		CHECK((batch.size() == 2 || bytes <= config.max_response_bytes));
		held = batch.back().sequence();
	}
	CHECK(held == last);
	CHECK(requests < 50);

	// peers pull by origin with the same budget rule
	CHECK(sync.get_envelopes(sequence_number{2}, sequence_number{}).size() >= 2);
}

// (7) validate/apply split behaves like commit_block
TEST_CASE("chain_sync validate and apply", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::require_all_seen});

	test_block_creator creator;
	auto b1 = creator.test_user_change();
	CHECK(!sync.validate(b1));
	auto committed = sync.apply(b1);
	CHECK(committed.sequence() == sequence_number{1});
	CHECK(sync.current_sequence_number() == sequence_number{1});

	// after apply the same block is a duplicate
	CHECK(bool(sync.validate(b1)));
	CHECK(check_result_error(sync.commit_block(b1), protocol::errc::record_already_committed));

	auto b2 = creator.test_data_change();
	CHECK(!sync.validate(b2));
	CHECK(sync.commit_block(b2));
}


// (8) a rebased duplicate (same op id, different tag) of a committed record is rejected
TEST_CASE("chain_sync op id dedup", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::allow_all});

	test_block_creator creator;
	CHECK(sync.commit_block(creator.test_user_change()));

	auto op = securepath::test::random_octet_vector(16);
	creator.force_op_id = op;
	CHECK(sync.commit_block(creator.test_data_change()));

	// the "rebased" form: same operation id, everything else fresh
	creator.force_op_id = op;
	CHECK(check_result_error(sync.commit_block(creator.test_data_change()), protocol::errc::record_already_committed));

	// a fresh operation is fine
	CHECK(sync.commit_block(creator.test_data_change()));
}


// (9) signature verification under sign_records (plan 2.3, defect B7)
TEST_CASE("chain_sync signature verification", "[unit]") {
	remove_database_test_db();
	crypto::public_key_cache keys;
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name),
		chain_sync_config{sync_mode::allow_all, auth_mode::sign_records}, &keys);

	test_block_creator creator;

	// an unsigned record is rejected
	CHECK(check_result_error(sync.commit_block(creator.test_user_change()), protocol::errc::invalid_record));

	// a signer the server does not know is rejected
	auto key = crypto::generate_private_key();
	creator.signer = key;
	CHECK(check_result_error(sync.commit_block(creator.test_user_change()), protocol::errc::unknown_signer));

	// after the key is registered the records are accepted
	keys.insert(key.public_key());
	CHECK(sync.commit_block(creator.test_user_change()));
	CHECK(sync.commit_block(creator.test_data_change()));

	// a signature transplanted from another record must not verify
	auto b1 = creator.test_data_change();
	auto b2 = creator.test_data_change();
	auto transplanted = b2.to_auth_record<data_change_record>();
	transplanted.auth = b1.auth();
	CHECK(check_result_error(sync.commit_block(chain_block{transplanted}), protocol::errc::invalid_record));
}

// (RDS 5, RD10) the bounds of a data descriptor are a validity rule: judged the same on
// the commit path and on the foreign path, and they say nothing about the data itself
TEST_CASE("chain_sync data descriptor bounds", "[unit]") {
	remove_database_test_db();
	chain_sync sync(database::sqlite::create_sqlite_connection(db_name), chain_sync_config{sync_mode::allow_all});
	test_block_creator creator;
	REQUIRE(sync.commit_block(creator.test_user_change()));

	auto const digest = securepath::test::random_octet_vector(64);
	data_descriptor const good{3 * 1024 * 1024 + 48, 1024 * 1024, digest};
	REQUIRE(valid_data_descriptor(good));
	CHECK(valid_data_descriptor(data_descriptor{4112, chunk_size_range.lowest, digest}));
	CHECK(valid_data_descriptor(data_descriptor{4112, chunk_size_range.highest, digest}));

	std::vector<data_descriptor> const bad{
		data_descriptor{good.enc_size, chunk_size_range.lowest - 1, digest},
		data_descriptor{good.enc_size, chunk_size_range.highest + 1, digest},
		data_descriptor{good.enc_size, 0, digest},
		data_descriptor{0, good.chunk_size, digest},
		data_descriptor{16, good.chunk_size, digest},
		data_descriptor{good.enc_size, good.chunk_size, securepath::test::random_octet_vector(32)},
		data_descriptor{good.enc_size, good.chunk_size, {}},
		// more chunks than a manifest may name
		data_descriptor{(std::uint64_t{chunk_size_range.lowest} + 16) * (max_data_chunks + 1), chunk_size_range.lowest, digest}};
	for(auto const& d : bad) {
		CHECK(!valid_data_descriptor(d));
		auto creator_copy = creator;
		CHECK(check_result_error(sync.commit_block(creator_copy.test_data_change_with_data(d)), protocol::errc::invalid_record));
		auto foreign_creator = creator;
		CHECK(check_result_error(sync.commit_foreign(foreign_creator.test_data_change_with_data(d)), protocol::errc::invalid_record));
	}

	CHECK(sync.commit_block(creator.test_data_change_with_data(good)));
	auto foreign_creator = creator;
	CHECK(sync.commit_foreign(foreign_creator.test_data_change_with_data(data_descriptor{4112, chunk_size_range.lowest
		, securepath::test::random_octet_vector(64)})));
}

}
