// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <spsync/test/test_record_data.hpp>
#include "data_server_fixtures.hpp"

#include <spsync/server/server_lib/data_store.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/conversions.hpp>

#include <filesystem>
#include <map>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

std::string const db_name = "server_data_store_test.db";
std::filesystem::path const data_root = "server_data_store_test";

database::connection_ptr fresh_database(std::string const& name = db_name, std::filesystem::path const& root = data_root) {
	return test::fresh_database(name, root);
}

using test::client_data;
using test::is_error;
auto const make_data = [](std::size_t size, std::uint32_t chunk_size = 1000) { return test::make_client_data(size, chunk_size); };

/// no chunk without a manifest, and no upload with a manifest the descriptor does not
/// commit to: nothing of the data is known afterwards
void refused_before_upload(server_data_store& store, client_data const& data, time_point now) {
	auto const& id = data.descriptor.manifest_digest;
	// no chunk without a manifest
	CHECK(is_error(test::store_whole_chunk(store, id, 0, data.chunks.at(0), now), protocol::errc::no_such_upload));

	// not the manifest the descriptor commits to
	auto foreign = data.manifest;
	foreign.chunk_digests[2] = securepath::test::random_octet_vector(64);
	CHECK(is_error(store.open_upload(data.descriptor, foreign, now), protocol::errc::invalid_data_manifest));
	auto short_manifest = data.manifest;
	short_manifest.chunk_digests.pop_back();
	CHECK(is_error(store.open_upload(data.descriptor, short_manifest, now), protocol::errc::invalid_data_manifest));
	CHECK(!store.find(id));
}

/// junk dies at the edge: a changed chunk, a chunk of another position, a chunk past the end
void junk_refused(server_data_store& store, client_data const& data, time_point now) {
	auto const& id = data.descriptor.manifest_digest;
	auto junk = data.chunks.at(1);
	junk[7] ^= 0x01;
	CHECK(is_error(test::store_whole_chunk(store, id, 1, junk, now), protocol::errc::invalid_data_chunk));
	CHECK(is_error(test::store_whole_chunk(store, id, 1, data.chunks.at(2), now), protocol::errc::invalid_data_chunk));
	CHECK(is_error(test::store_whole_chunk(store, id, 5, data.chunks.at(0), now), protocol::errc::invalid_data_chunk));
	CHECK(store.find(id)->have.count() == 0);
}

/// the connection went: the next manifest is answered with what is held (two of the five
/// chunks); the same descriptor id with other sizes is not this data
void resumed_with_what_is_held(server_data_store& store, client_data const& data, time_point now) {
	auto resumed = store.open_upload(data.descriptor, data.manifest, now);
	REQUIRE(resumed);
	CHECK(resumed->count() == 2);
	CHECK(resumed->test(0));
	CHECK(resumed->test(3));
	CHECK(store.used_bytes() == data.descriptor.enc_size);

	// the same descriptor id with other sizes is not this data
	auto contradicting = data.descriptor;
	contradicting.chunk_size = 900;
	CHECK(is_error(store.open_upload(contradicting, data.manifest, now), protocol::errc::invalid_data_manifest));
}

}

// RD5: manifest first, then chunks checked against it; the reply to the manifest is the resume point
TEST_CASE("server data store upload and resume", "[unit]") {
	server_data_store store{fresh_database(), data_root};
	auto const now = clock_type::now();
	auto const data = make_data(4500);
	auto const& id = data.descriptor.manifest_digest;
	REQUIRE(data.chunks.size() == 5);

	CHECK(!store.find(id));
	CHECK(store.used_bytes() == 0);
	refused_before_upload(store, data, now);

	auto have = store.open_upload(data.descriptor, data.manifest, now);
	REQUIRE(have);
	CHECK(have->size() == 5);
	CHECK(have->count() == 0);
	CHECK(store.used_bytes() == data.descriptor.enc_size);
	junk_refused(store, data, now);

	auto stored = test::store_whole_chunk(store, id, 3, data.chunks.at(3), now);
	REQUIRE(stored);
	CHECK(!stored.value());
	CHECK(test::store_whole_chunk(store, id, 0, data.chunks.at(0), now));

	// the connection went: the next manifest is answered with what is held
	resumed_with_what_is_held(store, data, now);

	for(std::uint64_t no : {1u, 2u, 4u}) {
		auto res = test::store_whole_chunk(store, id, no, data.chunks.at(no), now);
		REQUIRE(res);
		CHECK(res.value() == (no == 4));
	}
	CHECK(store.find(id)->state == record_data_state::in_sync);
	for(auto const& [no, chunk] : data.chunks) {
		CHECK(store.chunks().read_chunk(id, no) == chunk);
	}

	// complete: a further manifest says so, and a chunk that is held is not taken again
	// (review O4: nothing is staged for it)
	auto again = store.open_upload(data.descriptor, data.manifest, now);
	REQUIRE(again);
	CHECK(again->complete());
	CHECK(is_error(store.begin_chunk(id, 2, now), protocol::errc::invalid_data_chunk));
	CHECK(store.find(id)->state == record_data_state::in_sync);
}

// (review C5) what the storage's data takes and the uploads on their way are counters:
// read from the tables when the store opens, kept up from then on
TEST_CASE("server data store counters", "[unit]") {
	auto db = fresh_database();
	auto const now = clock_type::now();
	auto const done = make_data(3000);
	auto const half = make_data(5000);
	{
		server_data_store store{db, data_root};
		CHECK(store.used_bytes() == 0);
		CHECK(store.uploads_in_progress() == 0);
		REQUIRE(store.open_upload(done.descriptor, done.manifest, now));
		REQUIRE(store.open_upload(half.descriptor, half.manifest, now));
		CHECK(store.uploads_in_progress() == 2);
		for(auto const& [no, chunk] : done.chunks) {
			REQUIRE(test::store_whole_chunk(store, done.descriptor.manifest_digest, no, chunk, now));
		}
		REQUIRE(test::store_whole_chunk(store, half.descriptor.manifest_digest, 0, half.chunks.at(0), now));
		CHECK(store.used_bytes() == done.descriptor.enc_size + half.descriptor.enc_size);
		CHECK(store.uploads_in_progress() == 1);
		// opened again: nothing is counted twice
		REQUIRE(store.open_upload(half.descriptor, half.manifest, now));
		REQUIRE(store.open_replica(done.descriptor, now));
		CHECK(store.used_bytes() == done.descriptor.enc_size + half.descriptor.enc_size);
		CHECK(store.uploads_in_progress() == 1);
	}
	// a store opened over the same tables counts the same
	server_data_store store{db, data_root};
	CHECK(store.used_bytes() == done.descriptor.enc_size + half.descriptor.enc_size);
	CHECK(store.uploads_in_progress() == 1);
	CHECK(store.release({done.descriptor.manifest_digest, securepath::test::random_octet_vector(64)}) == 1);
	CHECK(store.used_bytes() == half.descriptor.enc_size);
	CHECK(store.expire_incomplete(now + std::chrono::seconds{1}) == 1);
	CHECK(store.used_bytes() == 0);
	CHECK(store.uploads_in_progress() == 0);
}

// the same in pieces, as the wire brings a chunk
TEST_CASE("server data store chunks in pieces", "[unit]") {
	server_data_store store{fresh_database(), data_root};
	auto const now = clock_type::now();
	auto const data = make_data(1500);
	auto const& id = data.descriptor.manifest_digest;
	REQUIRE(data.chunks.size() == 5);

	CHECK(is_error(store.begin_chunk(id, 0, now), protocol::errc::no_such_upload));
	REQUIRE(store.open_upload(data.descriptor, data.manifest, now));
	CHECK(is_error(store.begin_chunk(id, 5, now), protocol::errc::invalid_data_chunk));

	// incomplete, then the wrong bytes: nothing is kept
	{
		auto incoming = store.begin_chunk(id, 0, now);
		REQUIRE(incoming);
		CHECK(incoming->append(0, octet_span{data.chunks.at(0)}.first(100)));
		CHECK(is_error(store.finish_chunk(id, incoming.value(), now), protocol::errc::invalid_data_chunk));
	}
	{
		auto junk = data.chunks.at(0);
		junk[0] ^= 0x01;
		auto incoming = store.begin_chunk(id, 0, now);
		REQUIRE(incoming);
		CHECK(incoming->append(0, junk));
		CHECK(is_error(store.finish_chunk(id, incoming.value(), now), protocol::errc::invalid_data_chunk));
	}
	CHECK(store.find(id)->have.count() == 0);

	for(auto const& [no, chunk] : data.chunks) {
		octet_span const all{chunk};
		auto incoming = store.begin_chunk(id, no, now);
		REQUIRE(incoming);
		auto const half = all.size() / 2;
		CHECK(incoming->append(0, all.first(half)));
		CHECK(incoming->append(half, all.subspan(half)));
		auto const kept = store.finish_chunk(id, incoming.value(), now);
		REQUIRE(kept);
		CHECK(kept.value() == (no == 4));
	}
	CHECK(store.find(id)->state == record_data_state::in_sync);
	CHECK(store.uploads_in_progress() == 0);
	for(auto const& [no, chunk] : data.chunks) {
		CHECK(store.chunks().read_chunk(id, no) == chunk);
	}
}

// RD10: resource quota - refuses uploads, never says anything about validity
TEST_CASE("server data store quota", "[unit]") {
	auto const now = clock_type::now();
	auto const small = make_data(100);      // pads to 4096
	auto const medium = make_data(6000);
	auto const big = make_data(20000);

	SECTION("single data size") {
		server_data_store store{fresh_database(), data_root, data_quota{medium.descriptor.enc_size, 0}};
		CHECK(store.open_upload(small.descriptor, small.manifest, now));
		CHECK(store.open_upload(medium.descriptor, medium.manifest, now));
		CHECK(is_error(store.open_upload(big.descriptor, big.manifest, now), protocol::errc::data_too_big));
		CHECK(!store.find(big.descriptor.manifest_digest));
	}

	SECTION("storage total with reservation") {
		auto const limit = small.descriptor.enc_size + medium.descriptor.enc_size;
		server_data_store store{fresh_database(), data_root, data_quota{0, limit}};
		// an opened upload reserves its whole size, held or not
		CHECK(store.open_upload(medium.descriptor, medium.manifest, now));
		CHECK(store.used_bytes() == medium.descriptor.enc_size);
		CHECK(is_error(store.open_upload(big.descriptor, big.manifest, now), protocol::errc::data_quota_exceeded));
		CHECK(store.open_upload(small.descriptor, small.manifest, now));
		CHECK(store.used_bytes() == limit);

		auto const another = make_data(100);
		CHECK(is_error(store.open_upload(another.descriptor, another.manifest, now), protocol::errc::data_quota_exceeded));
		CHECK(!store.find(another.descriptor.manifest_digest));

		// a resume of what is reserved is never refused, and works at the limit
		CHECK(store.open_upload(medium.descriptor, medium.manifest, now));
		for(auto const& [no, chunk] : medium.chunks) {
			CHECK(test::store_whole_chunk(store, medium.descriptor.manifest_digest, no, chunk, now));
		}
		CHECK(store.find(medium.descriptor.manifest_digest)->state == record_data_state::in_sync);

		// an expired reservation makes room again
		CHECK(store.expire_incomplete(now + 1s) == 1);
		CHECK(store.used_bytes() == medium.descriptor.enc_size);
		CHECK(store.open_upload(another.descriptor, another.manifest, now));
	}
}

// RD5: incomplete uploads expire, complete data never does
TEST_CASE("server data store expiry", "[unit]") {
	auto db = fresh_database();
	auto const t0 = clock_type::now();
	auto const done = make_data(3000);
	auto const stale = make_data(3000);
	auto const active = make_data(3000);
	{
		server_data_store store{db, data_root};
		for(auto const* d : {&done, &stale, &active}) {
			REQUIRE(store.open_upload(d->descriptor, d->manifest, t0));
			REQUIRE(test::store_whole_chunk(store, d->descriptor.manifest_digest, 0, d->chunks.at(0), t0));
		}
		for(auto const& [no, chunk] : done.chunks) {
			REQUIRE(test::store_whole_chunk(store, done.descriptor.manifest_digest, no, chunk, t0));
		}
		// one upload goes on an hour later
		REQUIRE(test::store_whole_chunk(store, active.descriptor.manifest_digest, 1, active.chunks.at(1), t0 + 1h));

		CHECK(store.expire_incomplete(t0) == 0);
	}

	// the bookkeeping survives a restart
	server_data_store store{db, data_root};
	CHECK(store.expire_incomplete(t0 + 30min) == 1);
	CHECK(!store.find(stale.descriptor.manifest_digest));
	CHECK(!std::filesystem::exists(data_root / to_hex(stale.descriptor.manifest_digest)));
	CHECK(store.find(done.descriptor.manifest_digest)->state == record_data_state::in_sync);
	auto const kept = store.find(active.descriptor.manifest_digest);
	REQUIRE(kept);
	CHECK(kept->have.count() == 2);
	CHECK(store.used_bytes() == done.descriptor.enc_size + active.descriptor.enc_size);

	// the expired one starts over
	auto have = store.open_upload(stale.descriptor, stale.manifest, t0 + 2h);
	REQUIRE(have);
	CHECK(have->count() == 0);

	CHECK(store.expire_incomplete(t0 + 3h) == 2);
	CHECK(store.find(done.descriptor.manifest_digest));
	CHECK(store.used_bytes() == done.descriptor.enc_size);
	CHECK(store.expire_incomplete(t0 + 100h) == 0);
}

// RD9: data no record names any more goes, rows and chunks, and its room is free again
TEST_CASE("server data store release", "[unit]") {
	auto const now = clock_type::now();
	auto const kept = make_data(3000);
	auto const dead = make_data(5000);
	auto const half = make_data(5000);
	auto const limit = kept.descriptor.enc_size + dead.descriptor.enc_size + half.descriptor.enc_size;
	server_data_store store{fresh_database(), data_root, data_quota{0, limit}};

	for(auto const* d : {&kept, &dead}) {
		REQUIRE(store.open_upload(d->descriptor, d->manifest, now));
		for(auto const& [no, chunk] : d->chunks) {
			REQUIRE(test::store_whole_chunk(store, d->descriptor.manifest_digest, no, chunk, now));
		}
	}
	// an upload in progress
	REQUIRE(store.open_upload(half.descriptor, half.manifest, now));
	REQUIRE(test::store_whole_chunk(store, half.descriptor.manifest_digest, 0, half.chunks.at(0), now));
	CHECK(store.used_bytes() == limit);
	CHECK(store.uploads_in_progress() == 1);

	CHECK(store.release({}) == 0);
	CHECK(store.release({securepath::test::random_octet_vector(64)}) == 0);
	CHECK(store.release({dead.descriptor.manifest_digest, half.descriptor.manifest_digest
		, securepath::test::random_octet_vector(64)}) == 2);

	CHECK(!store.find(dead.descriptor.manifest_digest));
	CHECK(!store.find(half.descriptor.manifest_digest));
	CHECK(!std::filesystem::exists(data_root / to_hex(dead.descriptor.manifest_digest)));
	CHECK(!std::filesystem::exists(data_root / to_hex(half.descriptor.manifest_digest)));
	CHECK(store.uploads_in_progress() == 0);
	CHECK(store.used_bytes() == kept.descriptor.enc_size);
	// what was not released is untouched
	CHECK(store.find(kept.descriptor.manifest_digest)->state == record_data_state::in_sync);
	CHECK(store.chunks().read_chunk(kept.descriptor.manifest_digest, 0) == kept.chunks.at(0));

	// a chunk of the released upload that was still on its way
	CHECK(is_error(test::store_whole_chunk(store, half.descriptor.manifest_digest, 1, half.chunks.at(1), now), protocol::errc::no_such_upload));
	// the room is there again, and released again is nothing
	CHECK(store.open_upload(dead.descriptor, dead.manifest, now));
	CHECK(store.release({half.descriptor.manifest_digest}) == 0);
}

// RD10: served octets per window, windows fixed to the clock
// (RDS 10) the copy of a data another data server holds: known by its descriptor first,
// reserved like an upload, filled through the chunk store with a client's verification
TEST_CASE("server data store replica", "[unit]") {
	auto const db = fresh_database();
	auto const now = clock_type::now();
	auto const data = make_data(2500, 1000);
	auto const& id = data.descriptor.manifest_digest;
	auto const limit = data.descriptor.enc_size + 100;
	CHECK(is_error(server_data_store{db, data_root, data_quota{1000, 0}}.open_replica(data.descriptor, now), protocol::errc::data_too_big));
	server_data_store store{db, data_root, data_quota{0, limit}};

	auto const opened = store.open_replica(data.descriptor, now);
	REQUIRE(opened);
	CHECK(opened.value().count() == 0);
	CHECK(opened.value().size() == data.descriptor.chunk_count());
	CHECK(store.used_bytes() == data.descriptor.enc_size);
	CHECK(store.uploads_in_progress() == 1);
	// nothing to serve yet: no manifest
	CHECK(is_error(store.open_download(data.descriptor), protocol::errc::data_not_held));
	// again is the same reservation; another data does not fit, a contradiction is refused
	CHECK(store.open_replica(data.descriptor, now));
	CHECK(store.used_bytes() == data.descriptor.enc_size);
	CHECK(is_error(store.open_replica(make_data(2500, 1000).descriptor, now), protocol::errc::data_quota_exceeded));
	auto contradicting = data.descriptor;
	contradicting.enc_size += 1000;
	CHECK(is_error(store.open_replica(contradicting, now), protocol::errc::invalid_data_manifest));

	// the pull: manifest, then chunks, each checked against it
	auto& chunks = store.chunks();
	REQUIRE(chunks.set_manifest(id, data.manifest));
	auto tampered = data.chunks.at(0);
	tampered[5] ^= 0x01;
	CHECK(!chunks.store_chunk(id, 0, tampered));
	CHECK(chunks.store_chunk(id, 0, data.chunks.at(0)));
	CHECK(!store.replica_pulled(id, now));
	CHECK(store.open_replica(data.descriptor, now).value().count() == 1);
	for(std::uint64_t no = 1; no != data.descriptor.chunk_count(); ++no) {
		CHECK(chunks.store_chunk(id, no, data.chunks.at(no)));
	}
	CHECK(store.replica_pulled(id, now));
	CHECK(store.uploads_in_progress() == 0);
	CHECK(store.find(id)->state == record_data_state::in_sync);
	CHECK(store.open_replica(data.descriptor, now).value().complete());
	CHECK(store.complete_data().size() == 1);
	// and it is served like any other
	CHECK(store.open_download(data.descriptor));
}

TEST_CASE("transfer budget", "[unit]") {
	auto const t0 = time_point{std::chrono::seconds{1000000}};

	transfer_budget unlimited;
	CHECK(unlimited.charge(std::uint64_t{1} << 40, t0));

	transfer_budget budget{transfer_quota{1000, 100s}};
	CHECK(budget.used(t0) == 0);
	CHECK(budget.charge(600, t0));
	CHECK(budget.charge(400, t0 + 50s));
	CHECK(budget.used(t0 + 50s) == 1000);
	// full: nothing more fits, and what does not fit is not counted
	CHECK(!budget.charge(1, t0 + 60s));
	CHECK(!budget.charge(5000, t0 + 60s));
	CHECK(budget.used(t0 + 60s) == 1000);
	CHECK(budget.retry_after(t0 + 60s) == 40);
	CHECK(budget.retry_after(t0) == 100);

	// the next window starts empty
	CHECK(budget.used(t0 + 100s) == 0);
	CHECK(budget.charge(1000, t0 + 100s));
	CHECK(!budget.charge(1, t0 + 199s));
	CHECK(budget.retry_after(t0 + 199s) == 1);
	// more than a whole window is never served at once
	CHECK(!budget.charge(1001, t0 + 200s));
}

}
