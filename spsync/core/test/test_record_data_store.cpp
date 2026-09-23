#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <spsync/test/test_record_data.hpp>

#include <spsync/core/data/chunk_files.hpp>
#include <spsync/core/data/data_state_table.hpp>
#include <spsync/core/data/have_bitmap.hpp>
#include <spsync/core/data/record_data_store.hpp>
#include <spsync/core/data/source_record_data.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/hash.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/conversions.hpp>

#include <filesystem>
#include <limits>
#include <fstream>
#include <map>

namespace securepath::sync {
namespace {

std::string const db_name = "record_data_store_test.db";
std::filesystem::path const data_root = "record_data_store_test";

database::connection_ptr fresh_database(std::string const& name = db_name, std::filesystem::path const& root = data_root) {
	return test::fresh_database(name, root);
}

using test::test_group_key;

/// deterministic plaintext, so big data never has to be held to be compared
octet_vector pattern_bytes(std::uint64_t offset, std::size_t size) {
	octet_vector ret(size);
	for(std::size_t i = 0; i != size; ++i) {
		std::uint64_t const pos = offset + i;
		ret[i] = static_cast<std::uint8_t>((pos * 2654435761u) >> 11);
	}
	return ret;
}

encrypted_data_result write_pattern(record_data_store& store, encryption_key const& key, std::uint64_t size
	, std::uint32_t chunk_size, std::size_t piece) {
	auto writer = store.create(key, chunk_size);
	for(std::uint64_t pos = 0; pos < size; pos += piece) {
		writer.write(pattern_bytes(pos, static_cast<std::size_t>(std::min<std::uint64_t>(piece, size - pos))));
	}
	return writer.finish();
}

octet_vector read_bytes(record_data& data, std::uint64_t offset, std::size_t size) {
	octet_vector ret(size);
	ret.resize(data.read(offset, ret.data(), ret.size()));
	return ret;
}

/// the ciphertext of a data as a transfer peer would hold it
struct remote_copy {
	data_manifest manifest;
	std::map<std::uint64_t, octet_vector> chunks;
};

remote_copy copy_of(record_data_store const& store, encrypted_data_result const& data) {
	remote_copy ret;
	ret.manifest = data.manifest;
	for(std::uint64_t no = 0; no != data.descriptor.chunk_count(); ++no) {
		ret.chunks[no] = store.read_chunk(data.descriptor.manifest_digest, no).value();
	}
	return ret;
}

std::filesystem::path chunk_path(data_id const& id, std::string const& name) {
	return data_root / to_hex(id) / name;
}

void flip_first_octet(std::filesystem::path const& path) {
	std::fstream f(path, std::ios::binary | std::ios::in | std::ios::out);
	char c = 0;
	f.read(&c, 1);
	c = static_cast<char>(c ^ 0x01);
	f.seekp(0);
	f.write(&c, 1);
}

}

TEST_CASE("have bitmap", "[unit]") {
	have_bitmap none;
	CHECK(none.size() == 0);
	CHECK(none.complete());
	CHECK(none.first_missing() == 0);

	have_bitmap have{11};
	CHECK(have.octets().size() == 2);
	CHECK(have.count() == 0);
	CHECK(!have.complete());
	CHECK(have.first_missing() == 0);

	have.set(0);
	have.set(1);
	have.set(9);
	have.set(11); // past the end
	CHECK(have.test(0));
	CHECK(have.test(9));
	CHECK(!have.test(2));
	CHECK(!have.test(11));
	CHECK(have.count() == 3);
	CHECK(have.first_missing() == 2);
	CHECK(have.first_missing(9) == 10);

	// what the table stores gives the same bitmap back
	CHECK(have_bitmap{11, have.octets()} == have);

	have.set(1, false);
	CHECK(!have.test(1));
	CHECK(have.first_missing() == 1);

	have.set_all();
	CHECK(have.complete());
	CHECK(have.count() == 11);
	CHECK(have.first_missing() == 11);
	// the unused bits of the last octet stay zero
	CHECK(have.octets().back() == 0x07);

	have.clear();
	CHECK(have.count() == 0);

	// stored octets of another length or with stray bits are normalised
	CHECK(have_bitmap{11, octet_vector{0xff}}.count() == 8);
	CHECK(have_bitmap{11, octet_vector{0xff, 0xff, 0xff}}.count() == 11);
	CHECK(have_bitmap{11, octet_vector{}}.count() == 0);
}

TEST_CASE("chunk files", "[unit]") {
	std::filesystem::remove_all(data_root);
	chunk_files files{data_root};

	data_id const id = securepath::test::random_octet_vector(64);
	auto const c0 = securepath::test::random_octet_vector(300);
	auto const c1 = securepath::test::random_octet_vector(20);

	CHECK(!files.has(id, 0));
	CHECK(!files.read(id, 0));
	CHECK_NOTHROW(files.remove(id));
	CHECK_NOTHROW(files.remove_chunk(id, 0));

	files.write(id, 0, c0);
	files.write(id, 1, c1);
	CHECK(files.has(id, 0));
	CHECK(files.read(id, 0) == c0);
	CHECK(files.read(id, 1) == c1);
	CHECK(!files.has(id, 2));

	// replaced, no temporary file left
	files.write(id, 1, c0);
	CHECK(files.read(id, 1) == c0);
	CHECK(std::distance(std::filesystem::directory_iterator{data_root / to_hex(id)}, {}) == 2);

	files.remove_chunk(id, 0);
	CHECK(!files.has(id, 0));
	CHECK(files.has(id, 1));
	files.remove(id);
	CHECK(!files.has(id, 1));
	CHECK(!std::filesystem::exists(data_root / to_hex(id)));

	// an empty id would name the root
	CHECK_THROWS(files.write(data_id{}, 0, c0));
	CHECK_THROWS(files.remove(data_id{}));
	CHECK_THROWS(files.write_staged("../x", 0, c0));
	CHECK_THROWS(files.discard_staging(""));

	SECTION("staging") {
		auto const stage = files.begin_staging();
		files.write_staged(stage, 0, c0);
		files.write_staged(stage, 1, c1);
		CHECK(!files.has(id, 0));
		files.commit_staging(stage, id);
		CHECK(files.read(id, 0) == c0);
		CHECK(files.read(id, 1) == c1);

		// a data already held keeps its chunks
		auto const again = files.begin_staging();
		files.write_staged(again, 0, c1);
		files.commit_staging(again, id);
		CHECK(files.read(id, 0) == c0);

		auto const dropped = files.begin_staging();
		files.write_staged(dropped, 0, c0);
		files.discard_staging(dropped);
		auto const stale = files.begin_staging();
		files.write_staged(stale, 0, c0);
		files.clear_staging();
		CHECK(!std::filesystem::exists(data_root / ".staging"));
		CHECK(files.read(id, 0) == c0);
	}
}

TEST_CASE("data state table", "[unit]") {
	auto db = fresh_database();
	data_descriptor const d{5080, 1000, securepath::test::random_octet_vector(64)};
	data_manifest manifest;
	for(std::uint64_t i = 0; i != d.chunk_count(); ++i) {
		manifest.chunk_digests.push_back(securepath::test::random_octet_vector(64));
	}

	std::uint64_t local_id = 0;
	{
		data_state_table table{db};
		CHECK(!table.find(d.manifest_digest));
		CHECK(table.all_ids().empty());

		local_id = table.ensure(d);
		CHECK(table.ensure(d) == local_id);
		CHECK(table.all_ids() == std::vector<std::uint64_t>{local_id});

		auto row = table.find(d.manifest_digest);
		REQUIRE(row);
		CHECK(row->local_id == local_id);
		CHECK(row->descriptor == d);
		CHECK(row->state == record_data_state::deferred);
		CHECK(row->have.size() == d.chunk_count());
		CHECK(row->have.count() == 0);
		CHECK(!table.manifest(local_id));

		row->have.set(2);
		table.set_have(local_id, row->have);
		table.set_state(local_id, record_data_state::download_pending);
		table.set_manifest(local_id, manifest);
	}

	// persisted
	data_state_table table{db};
	auto row = table.find(local_id);
	REQUIRE(row);
	CHECK(row->descriptor == d);
	CHECK(row->state == record_data_state::download_pending);
	CHECK(row->have.count() == 1);
	CHECK(row->have.test(2));
	CHECK(table.manifest(local_id) == manifest);

	// another data gets another row
	data_descriptor const other{4112, 4096, securepath::test::random_octet_vector(64)};
	CHECK(table.ensure(other) != local_id);
	CHECK(table.all_ids().size() == 2);

	table.remove(local_id);
	CHECK(!table.find(local_id));
	CHECK(!table.find(d.manifest_digest));
	CHECK(table.all_ids().size() == 1);
}

// RD6: writes in any pieces, reads at any offset, both across chunk boundaries
TEST_CASE("record data store offset reads and writes across chunk boundaries", "[unit]") {
	auto db = fresh_database();
	record_data_store store{db, data_root};
	auto const key = test_group_key();

	std::uint64_t const size = 10500;
	std::uint32_t const chunk_size = 1000;
	auto const data = write_pattern(store, key, size, chunk_size, 777);
	CHECK(data.header.plain_size == size);
	CHECK(data.manifest.matches(data.descriptor));

	auto const row = store.find(data.descriptor.manifest_digest);
	REQUIRE(row);
	CHECK(row->state == record_data_state::upload_pending);
	CHECK(row->have.complete());
	CHECK(store.manifest(data.descriptor.manifest_digest) == data.manifest);

	auto handle = store.open({key}, data.descriptor, data.header);
	REQUIRE(handle);
	CHECK(handle->local_id() == row->local_id);
	CHECK(handle->size() == size);
	CHECK(handle->available_size() == size);
	CHECK(handle->state() == record_data_state::upload_pending);

	CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, size));
	CHECK(read_bytes(*handle, 995, 10) == pattern_bytes(995, 10));
	CHECK(read_bytes(*handle, 999, 2) == pattern_bytes(999, 2));
	CHECK(read_bytes(*handle, 1000, 1000) == pattern_bytes(1000, 1000));
	CHECK(read_bytes(*handle, 2500, 5100) == pattern_bytes(2500, 5100));
	// the end of the data, not of the padding
	CHECK(read_bytes(*handle, size - 10, 100) == pattern_bytes(size - 10, 10));
	CHECK(read_bytes(*handle, size, 10).empty());
	CHECK(read_bytes(*handle, size + 5000, 10).empty());
	CHECK(read_bytes(*handle, 0, 0).empty());

	// a stored data is what its descriptor says
	std::uint8_t const octet = 0;
	CHECK_THROWS(handle->write(0, &octet, 1));

	SECTION("empty data") {
		auto const empty = write_pattern(store, key, 0, chunk_size, 777);
		auto h = store.open({key}, empty.descriptor, empty.header);
		REQUIRE(h);
		CHECK(h->size() == 0);
		CHECK(h->available_size() == 0);
		CHECK(read_bytes(*h, 0, 10).empty());
		// RD11: the padding is there all the same
		CHECK(store.find(empty.descriptor.manifest_digest)->have.size() == 5);
	}

	SECTION("a contradicting descriptor opens nothing") {
		auto wrong = data.descriptor;
		wrong.enc_size += chunk_size;
		CHECK(!store.open({key}, wrong, data.header));
		CHECK_THROWS(store.open({}, data.descriptor, data.header));
	}

	SECTION("the handle outlives the store") {
		auto kept = std::make_unique<record_data_store>(db, data_root);
		auto h = kept->open({key}, data.descriptor, data.header);
		kept.reset();
		CHECK(read_bytes(*h, 0, size) == pattern_bytes(0, size));
	}
}

// RD6: eviction keeps the record side untouched and the data refetchable
TEST_CASE("record data store evict and refetch", "[unit]") {
	auto db = fresh_database();
	record_data_store store{db, data_root};
	auto const key = test_group_key();

	std::uint64_t const size = 6000;
	auto const data = write_pattern(store, key, size, 1000, 4096);
	auto const& id = data.descriptor.manifest_digest;
	auto const remote = copy_of(store, data);
	auto handle = store.open({key}, data.descriptor, data.header);
	REQUIRE(handle);

	// the only copy stays
	CHECK(!store.evict(id));
	handle->remove_data();
	CHECK(handle->available_size() == size);
	CHECK(!store.evict(securepath::test::random_octet_vector(64)));

	store.set_state(id, record_data_state::in_sync);
	CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, size));
	handle->remove_data();
	CHECK(handle->state() == record_data_state::removed);
	CHECK(handle->size() == size);
	CHECK(handle->available_size() == 0);
	CHECK(read_bytes(*handle, 0, size).empty());
	CHECK(store.find(id)->have.count() == 0);
	CHECK(!store.read_chunk(id, 0));
	CHECK(!std::filesystem::exists(data_root / to_hex(id)));

	// refetch: every chunk is checked against the manifest the descriptor commits to
	auto tampered = remote.chunks.at(0);
	tampered[10] ^= 0x01;
	CHECK(!store.store_chunk(id, 0, tampered));
	CHECK(!store.store_chunk(id, 0, remote.chunks.at(1)));
	CHECK(!store.store_chunk(id, remote.chunks.size(), remote.chunks.at(0)));
	CHECK(store.find(id)->have.count() == 0);

	for(auto const& [no, chunk] : remote.chunks) {
		CHECK(store.find(id)->state == record_data_state::removed);
		CHECK(store.store_chunk(id, no, chunk));
	}
	CHECK(handle->state() == record_data_state::in_sync);
	CHECK(handle->available_size() == size);
	CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, size));
	// again is fine
	CHECK(store.store_chunk(id, 0, remote.chunks.at(0)));
}

// (review 2026-09-21) what an eviction and a removed row must not do to handles and states
TEST_CASE("record data store evictions and stale handles", "[unit]") {
	auto db = fresh_database();
	record_data_store store{db, data_root};
	auto const key = test_group_key();
	std::uint64_t const size = 6000;
	auto const data = write_pattern(store, key, size, 1000, 4096);
	auto const& id = data.descriptor.manifest_digest;
	store.set_state(id, record_data_state::in_sync);

	SECTION("another handle's cached chunk goes with the chunks") {
		auto reader = store.open({key}, data.descriptor, data.header);
		auto other = store.open({key}, data.descriptor, data.header);
		// reader has chunk 0 decrypted in its cache
		CHECK(read_bytes(*reader, 0, 100) == pattern_bytes(0, 100));
		other->remove_data();
		CHECK(reader->available_size() == 0);
		CHECK(read_bytes(*reader, 0, 100).empty());
	}

	SECTION("an eviction changes what it is about") {
		// held -> removed
		CHECK(store.evict(id));
		CHECK(store.find(id)->state == record_data_state::removed);
		// the tombstone of a prune, a data never held, a download on its way: as they were
		for(auto const state : {record_data_state::pruned, record_data_state::deferred, record_data_state::download_pending
			, record_data_state::remote_not_complete, record_data_state::invalid}) {
			store.set_state(id, state);
			CHECK(store.evict(id));
			CHECK(store.find(id)->state == state);
		}
	}

	SECTION("a handle that outlives its row is not another data's") {
		auto stale = store.open({key}, data.descriptor, data.header);
		REQUIRE(stale->state() == record_data_state::in_sync);
		// the row goes (a rollback and the sweep that follows), another data comes
		CHECK(store.remove({id}) == 1);
		auto const next = write_pattern(store, key, 3000, 1000, 4096);
		REQUIRE(store.find(next.descriptor.manifest_digest));
		CHECK(store.find(next.descriptor.manifest_digest)->state == record_data_state::upload_pending);

		CHECK(stale->state() == record_data_state::invalid);
		CHECK(stale->available_size() == 0);
		stale->set_state(record_data_state::in_sync);
		CHECK(store.find(next.descriptor.manifest_digest)->state == record_data_state::upload_pending);
		// and the key of the row that went is not given out again
		CHECK(store.find(next.descriptor.manifest_digest)->local_id != stale->local_id());
	}
}

// (RDS 9) the retention policy of the storage let a data go: like an eviction, but the
// caller decides (a data still to be uploaded included) and the state says why
TEST_CASE("record data store prune", "[unit]") {
	auto db = fresh_database();
	record_data_store store{db, data_root};
	auto const key = test_group_key();

	std::uint64_t const size = 6000;
	auto const data = write_pattern(store, key, size, 1000, 4096);
	auto const& id = data.descriptor.manifest_digest;
	auto const remote = copy_of(store, data);
	auto handle = store.open({key}, data.descriptor, data.header);
	REQUIRE(handle);
	REQUIRE(handle->state() == record_data_state::upload_pending);

	CHECK(!store.prune(securepath::test::random_octet_vector(64)));
	CHECK(store.prune(id));
	CHECK(handle->state() == record_data_state::pruned);
	CHECK(handle->size() == size);
	CHECK(handle->available_size() == 0);
	CHECK(read_bytes(*handle, 0, size).empty());
	CHECK(!std::filesystem::exists(data_root / to_hex(id)));
	// the row stays with the record that names the data, and what is gone is no source
	auto const row = store.find(id);
	REQUIRE(row);
	CHECK(row->have.count() == 0);
	CHECK(row->descriptor == data.descriptor);
	CHECK(!store.find_content(data.header.content_digest, {}));
	// again is fine
	CHECK(store.prune(id));

	// a server that has not let it go yet still serves it
	for(auto const& [no, chunk] : remote.chunks) {
		CHECK(store.store_chunk(id, no, chunk));
	}
	CHECK(handle->state() == record_data_state::in_sync);
	CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, size));
}

// the receiving side: a record named the data, the bytes come later and in any order
TEST_CASE("record data store download into another store", "[unit]") {
	auto db = fresh_database();
	record_data_store origin{db, data_root};
	auto const key = test_group_key();
	std::uint32_t const chunk_size = 1000;
	std::uint64_t const size = 4500;
	auto const data = write_pattern(origin, key, size, chunk_size, 1500);
	auto const& id = data.descriptor.manifest_digest;
	auto const remote = copy_of(origin, data);

	std::string const other_db = "record_data_store_test_b.db";
	std::filesystem::path const other_root = "record_data_store_test_b";
	record_data_store store{fresh_database(other_db, other_root), other_root};

	CHECK(!store.find(id));
	auto handle = store.open({key}, data.descriptor, data.header);
	REQUIRE(handle);
	CHECK(handle->state() == record_data_state::deferred);
	CHECK(handle->size() == size);
	CHECK(handle->available_size() == 0);
	CHECK(read_bytes(*handle, 0, size).empty());

	// no chunk without the manifest, no manifest but the committed one
	CHECK(!store.store_chunk(id, 0, remote.chunks.at(0)));
	auto foreign = remote.manifest;
	foreign.chunk_digests[1] = securepath::test::random_octet_vector(64);
	CHECK(!store.set_manifest(id, foreign));
	CHECK(!store.set_manifest(securepath::test::random_octet_vector(64), remote.manifest));
	CHECK(store.set_manifest(id, remote.manifest));

	store.set_state(id, record_data_state::download_pending);
	CHECK(store.store_chunk(id, 2, remote.chunks.at(2)));
	CHECK(store.store_chunk(id, 0, remote.chunks.at(0)));
	CHECK(handle->state() == record_data_state::download_pending);
	CHECK(handle->available_size() == 2 * chunk_size);
	CHECK(store.find(id)->have.first_missing() == 1);

	// a read stops at the gap and works behind it
	CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, chunk_size));
	CHECK(read_bytes(*handle, 2 * chunk_size + 5, 100) == pattern_bytes(2 * chunk_size + 5, 100));
	CHECK(read_bytes(*handle, chunk_size, 10).empty());

	for(auto const& [no, chunk] : remote.chunks) {
		CHECK(store.store_chunk(id, no, chunk));
	}
	CHECK(handle->state() == record_data_state::in_sync);
	CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, size));
}

// D9: colliding key rotations leave several keys under one sequence
TEST_CASE("record data store key candidates", "[unit]") {
	auto db = fresh_database();
	record_data_store store{db, data_root};
	auto const key = test_group_key();
	auto const other = test_group_key();
	auto const data = write_pattern(store, key, 3000, 1000, 3000);
	store.set_state(data.descriptor.manifest_digest, record_data_state::in_sync);

	auto handle = store.open({other, key}, data.descriptor, data.header);
	REQUIRE(handle);
	CHECK(read_bytes(*handle, 0, 3000) == pattern_bytes(0, 3000));
	CHECK(read_bytes(*handle, 1500, 1000) == pattern_bytes(1500, 1000));
	CHECK(handle->state() == record_data_state::in_sync);

	// RD3: chunks the manifest names but no key authenticates make the data invalid
	auto blind = store.open({other}, data.descriptor, data.header);
	REQUIRE(blind);
	CHECK(read_bytes(*blind, 0, 3000).empty());
	CHECK(blind->state() == record_data_state::invalid);
}

// bit rot is not the author's fault: the chunk goes and is fetched again
TEST_CASE("record data store corrupted chunk", "[unit]") {
	auto db = fresh_database();
	record_data_store store{db, data_root};
	auto const key = test_group_key();
	std::uint64_t const size = 5000;
	auto const data = write_pattern(store, key, size, 1000, 5000);
	auto const& id = data.descriptor.manifest_digest;
	auto const remote = copy_of(store, data);
	auto handle = store.open({key}, data.descriptor, data.header);
	REQUIRE(handle);

	SECTION("refetchable") {
		store.set_state(id, record_data_state::in_sync);
		flip_first_octet(chunk_path(id, "00000001"));
		CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, 1000));
		CHECK(handle->state() == record_data_state::download_pending);
		CHECK(!store.find(id)->have.test(1));
		CHECK(!std::filesystem::exists(chunk_path(id, "00000001")));

		// a chunk file that went missing
		std::filesystem::remove(chunk_path(id, "00000003"));
		CHECK(!store.read_chunk(id, 3));
		CHECK(!store.find(id)->have.test(3));

		CHECK(store.store_chunk(id, 1, remote.chunks.at(1)));
		CHECK(handle->state() == record_data_state::download_pending);
		CHECK(store.store_chunk(id, 3, remote.chunks.at(3)));
		CHECK(handle->state() == record_data_state::in_sync);
		CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, size));
	}

	SECTION("the only copy") {
		flip_first_octet(chunk_path(id, "00000001"));
		CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, 1000));
		CHECK(handle->state() == record_data_state::invalid);
	}
}

TEST_CASE("record data store writer leaves nothing behind", "[unit]") {
	auto db = fresh_database();
	auto const key = test_group_key();
	{
		record_data_store store{db, data_root};
		{
			auto dropped = store.create(key, 1000);
			dropped.write(pattern_bytes(0, 2500));
			CHECK(!std::filesystem::is_empty(data_root / ".staging"));
		}
		CHECK(std::filesystem::is_empty(data_root / ".staging"));

		auto writer = store.create(key, 1000);
		auto moved = std::move(writer);
		moved.write(pattern_bytes(0, 100));
		auto const data = moved.finish();
		CHECK_THROWS(moved.write(pattern_bytes(0, 1)));
		CHECK_THROWS(moved.finish());
		CHECK(std::filesystem::is_empty(data_root / ".staging"));
		CHECK(store.find(data.descriptor.manifest_digest));
		CHECK_THROWS(store.create(key, 0));
		CHECK(std::filesystem::is_empty(data_root / ".staging"));
	}

	// what a crash left in the staging area goes when the store opens
	chunk_files files{data_root};
	files.write_staged(files.begin_staging(), 0, pattern_bytes(0, 10));
	record_data_store store{db, data_root};
	CHECK(!std::filesystem::exists(data_root / ".staging"));
}

// RD9: data nothing references is dropped, rows and chunks
TEST_CASE("record data store remove unreferenced", "[unit]") {
	auto db = fresh_database();
	record_data_store store{db, data_root};
	auto const key = test_group_key();
	auto const kept = write_pattern(store, key, 100, 1000, 100);
	auto const dead = write_pattern(store, key, 200, 1000, 100);

	CHECK(store.remove({}) == 0);
	CHECK(store.remove({securepath::test::random_octet_vector(64)}) == 0);
	CHECK(store.remove({dead.descriptor.manifest_digest, securepath::test::random_octet_vector(64)}) == 1);
	CHECK(store.find(kept.descriptor.manifest_digest));
	CHECK(!store.find(dead.descriptor.manifest_digest));
	CHECK(!std::filesystem::exists(data_root / to_hex(dead.descriptor.manifest_digest)));
	CHECK(std::filesystem::exists(data_root / to_hex(kept.descriptor.manifest_digest)));

	// a handle of a dropped data
	auto handle = store.open({key}, kept.descriptor, kept.header);
	CHECK(store.remove({kept.descriptor.manifest_digest}) == 1);
	CHECK(handle->state() == record_data_state::invalid);
	CHECK(read_bytes(*handle, 0, 100).empty());
}

// multi-megabyte data goes through in pieces: neither side ever holds more than a chunk
TEST_CASE("record data store streams big data", "[unit]") {
	auto db = fresh_database();
	record_data_store store{db, data_root};
	auto const key = test_group_key();

	std::uint64_t const size = 24 * 1024 * 1024 + 12345;
	std::uint32_t const chunk_size = 1024 * 1024;
	auto const data = write_pattern(store, key, size, chunk_size, 64 * 1024);
	CHECK(data.header.plain_size == size);
	CHECK(data.descriptor.chunk_count() >= 25);
	auto const dir = data_root / to_hex(data.descriptor.manifest_digest);
	CHECK(static_cast<std::uint64_t>(std::distance(std::filesystem::directory_iterator{dir}, {})) == data.descriptor.chunk_count());

	auto handle = store.open({key}, data.descriptor, data.header);
	REQUIRE(handle);
	crypto::hash_stream content;
	std::size_t const piece = 100000;
	std::uint64_t pos = 0;
	bool same = true;
	octet_vector bytes = read_bytes(*handle, pos, piece);
	while(!bytes.empty()) {
		same = same && bytes == pattern_bytes(pos, bytes.size());
		content.update(bytes);
		pos += bytes.size();
		bytes = read_bytes(*handle, pos, piece);
	}
	CHECK(same);
	CHECK(pos == size);
	CHECK(content.final() == data.header.content_digest);

	// random access decrypts the covering chunks only
	CHECK(read_bytes(*handle, 17 * std::uint64_t{chunk_size} - 3, 6) == pattern_bytes(17 * std::uint64_t{chunk_size} - 3, 6));
}

// (RDS 3) what an application hands to the engine as the source of a data
TEST_CASE("record data sources", "[unit]") {
	auto const content = pattern_bytes(0, 10000);

	SECTION("memory") {
		memory_record_data source{content};
		CHECK(source.size() == content.size());
		CHECK(source.available_size() == content.size());
		CHECK(source.local_id() == 0);
		CHECK(read_bytes(source, 0, content.size()) == content);
		CHECK(read_bytes(source, 9990, 100) == pattern_bytes(9990, 10));
		CHECK(read_bytes(source, 10000, 10).empty());

		// grows by writes at or before the end
		auto const more = pattern_bytes(10000, 500);
		CHECK(source.write(10000, more.data(), more.size()) == more.size());
		CHECK(source.size() == 10500);
		CHECK(read_bytes(source, 0, 10500) == pattern_bytes(0, 10500));
		CHECK(source.write(20000, more.data(), more.size()) == 0);
		CHECK(source.write(100, content.data(), 50) == 50);
		CHECK(read_bytes(source, 100, 50) == pattern_bytes(0, 50));

		memory_record_data empty;
		CHECK(empty.size() == 0);
		CHECK(empty.write(0, content.data(), 10) == 10);
		CHECK(empty.size() == 10);
	}

	SECTION("file") {
		std::filesystem::path const path = "record_data_source_test.bin";
		{
			std::ofstream out(path, std::ios::binary | std::ios::trunc);
			out.write(reinterpret_cast<char const*>(content.data()), static_cast<std::streamsize>(content.size()));
		}
		file_record_data source{path};
		CHECK(source.size() == content.size());
		CHECK(read_bytes(source, 0, content.size()) == content);
		CHECK(read_bytes(source, 5000, 100) == pattern_bytes(5000, 100));
		CHECK(read_bytes(source, 9990, 100) == pattern_bytes(9990, 10));
		CHECK(read_bytes(source, 10000, 10).empty());
		// a read past the end does not break the next one
		CHECK(read_bytes(source, 0, 10) == pattern_bytes(0, 10));
		CHECK_THROWS(source.write(0, content.data(), 1));
		std::filesystem::remove(path);
		CHECK_THROWS(file_record_data{path});
	}
}

// (RDS 3, RD7) a source goes into the store in pieces
TEST_CASE("record data store copy from a source", "[unit]") {
	auto db = fresh_database();
	record_data_store store{db, data_root};
	auto const key = test_group_key();

	std::uint64_t const size = 700000;
	memory_record_data source{pattern_bytes(0, size)};
	auto writer = store.create(key, 100000);
	copy_record_data(source, writer);
	auto const data = writer.finish();
	CHECK(data.header.plain_size == size);

	auto handle = store.open({key}, data.descriptor, data.header);
	REQUIRE(handle);
	CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, size));

	// the chunk sizes of a descriptor add up to enc_size, the last one is short
	std::uint64_t sum = 0;
	for(std::uint64_t no = 0; no != data.descriptor.chunk_count(); ++no) {
		CHECK(data.descriptor.chunk_enc_size(no) == store.read_chunk(data.descriptor.manifest_digest, no)->size());
		sum += data.descriptor.chunk_enc_size(no);
	}
	CHECK(sum == data.descriptor.enc_size);
	CHECK(data.descriptor.chunk_enc_size(data.descriptor.chunk_count()) == 0);

	// a source that promises more than it has
	struct short_source : memory_record_data {
		using memory_record_data::memory_record_data;
		std::uint64_t size() const override { return memory_record_data::size() + 1; }
	};
	short_source liar{pattern_bytes(0, 1000)};
	auto refused = store.create(key, 100000);
	CHECK_THROWS(copy_record_data(liar, refused));

	memory_record_data nothing;
	auto empty = store.create(key, 100000);
	CHECK_NOTHROW(copy_record_data(nothing, empty));
	CHECK(empty.finish().header.plain_size == 0);
}

// a chunk never travels whole: pieces are read from the chunk file on the way out and
// appended to a staged file, hashed as they come, on the way in
TEST_CASE("record data store chunk pieces", "[unit]") {
	auto db = fresh_database();
	record_data_store origin{db, data_root};
	auto const key = test_group_key();
	auto const data = write_pattern(origin, key, 4500, 1000, 4500);
	auto const& id = data.descriptor.manifest_digest;
	auto const remote = copy_of(origin, data);
	auto const chunk_size = remote.chunks.at(0).size();

	SECTION("reading") {
		auto const& chunk = remote.chunks.at(1);
		CHECK(origin.read_chunk_piece(id, 1, 0, chunk_size) == chunk);
		CHECK(origin.read_chunk_piece(id, 1, 0, 300) == octet_vector(chunk.begin(), chunk.begin() + 300));
		CHECK(origin.read_chunk_piece(id, 1, 900, chunk_size - 900) == octet_vector(chunk.begin() + 900, chunk.end()));
		CHECK(origin.read_chunk_piece(id, 1, chunk_size, 0) == octet_vector{});
		// outside the chunk, a chunk that is not there
		CHECK(!origin.read_chunk_piece(id, 1, 900, chunk_size));
		CHECK(!origin.read_chunk_piece(id, 1, chunk_size + 1, 0));
		CHECK(!origin.read_chunk_piece(id, 99, 0, 10));
		CHECK(!origin.read_chunk_piece(securepath::test::random_octet_vector(64), 0, 0, 10));

		// (review 2026-09-21) an offset from the wire that wraps the range check is a
		// refused read like any other - and a refused read is no lost chunk: the offsets
		// come from whoever asks, the chunk stays where it is
		auto const huge = std::numeric_limits<std::uint64_t>::max();
		CHECK(!origin.read_chunk_piece(id, 1, huge, 2));
		CHECK(!origin.read_chunk_piece(id, 1, huge - 10, 11));
		CHECK(!origin.read_chunk_piece(id, 1, 1, static_cast<std::size_t>(huge)));
		CHECK(origin.find(id)->have.count() == data.descriptor.chunk_count());
		CHECK(origin.read_chunk_piece(id, 1, 0, chunk_size) == chunk);
	}

	SECTION("receiving") {
		std::string const other_db = "record_data_store_test_b.db";
		std::filesystem::path const other_root = "record_data_store_test_b";
		record_data_store store{fresh_database(other_db, other_root), other_root};
		auto const staging = other_root / ".staging";

		// nothing to receive before the data and its manifest are known
		CHECK(!store.begin_chunk(id, 0));
		REQUIRE(store.register_data(data.descriptor, data.manifest));
		CHECK(!store.begin_chunk(id, remote.chunks.size()));

		auto const& chunk = remote.chunks.at(0);
		octet_span const bytes{chunk};
		{
			auto incoming = store.begin_chunk(id, 0);
			REQUIRE(incoming);
			CHECK(incoming->chunk_no() == 0);
			CHECK(incoming->append(0, bytes.first(400)));
			CHECK(incoming->received() == 400);
			CHECK(!incoming->complete());
			// not done: finishing now keeps nothing
			CHECK(!incoming->finish());
			CHECK(store.find(id)->have.count() == 0);
		}
		{
			auto incoming = store.begin_chunk(id, 0);
			REQUIRE(incoming);
			CHECK(incoming->append(0, bytes.first(400)));
			// not the next piece: the chunk is lost
			CHECK(!incoming->append(500, bytes.subspan(500, 100)));
			CHECK(!incoming->append(400, bytes.subspan(400, 100)));
			CHECK(!incoming->finish());
		}
		{
			// (review 2026-09-21) the digest is of the pieces as they came, the file is
			// what is kept: a file that is not exactly the pieces - a write that ended
			// half way, anything that got in - is not adopted whatever the digest says
			auto incoming = store.begin_chunk(id, 0);
			REQUIRE(incoming);
			CHECK(incoming->append(0, bytes.first(400)));
			for(auto const& entry : std::filesystem::recursive_directory_iterator{staging}) {
				if(entry.is_regular_file()) {
					std::ofstream{entry.path(), std::ios::binary | std::ios::app} << "x";
				}
			}
			CHECK(incoming->append(400, bytes.subspan(400)));
			CHECK(incoming->complete());
			CHECK(!incoming->finish());
			CHECK(store.find(id)->have.count() == 0);
			CHECK(!store.read_chunk(id, 0));
		}
		CHECK(std::filesystem::is_empty(staging));
		{
			// dropped half way
			auto incoming = store.begin_chunk(id, 0);
			REQUIRE(incoming);
			CHECK(incoming->append(0, bytes.first(400)));
			CHECK(!std::filesystem::is_empty(staging));
		}
		CHECK(std::filesystem::is_empty(staging));
		{
			// the right size, the wrong bytes
			auto junk = chunk;
			junk[3] ^= 0x01;
			auto incoming = store.begin_chunk(id, 0);
			REQUIRE(incoming);
			CHECK(incoming->append(0, junk));
			CHECK(incoming->complete());
			CHECK(!incoming->finish());
			CHECK(store.find(id)->have.count() == 0);
			CHECK(std::filesystem::is_empty(staging));
		}

		// every chunk in three pieces, moved around as a caller keeps them
		for(auto const& [no, c] : remote.chunks) {
			octet_span const all{c};
			auto begun = store.begin_chunk(id, no);
			REQUIRE(begun);
			incoming_chunk incoming{std::move(*begun)};
			CHECK(incoming.append(0, all.first(100)));
			CHECK(incoming.append(100, all.subspan(100, 500)));
			// more octets than the chunk has
			CHECK(!incoming.append(600, octet_vector(c.size(), 0)));
			incoming_chunk again{std::move(*store.begin_chunk(id, no))};
			CHECK(again.append(0, all.first(600)));
			CHECK(again.append(600, all.subspan(600)));
			CHECK(again.complete());
			CHECK(again.finish());
		}
		CHECK(std::filesystem::is_empty(staging));
		CHECK(store.find(id)->state == record_data_state::in_sync);
		auto handle = store.open({key}, data.descriptor, data.header);
		REQUIRE(handle);
		CHECK(read_bytes(*handle, 0, 4500) == pattern_bytes(0, 4500));

		// a chunk that is held already: received fine, the held one stays
		auto incoming = store.begin_chunk(id, 2);
		REQUIRE(incoming);
		CHECK(incoming->append(0, remote.chunks.at(2)));
		CHECK(incoming->finish());
		CHECK(std::filesystem::is_empty(staging));
	}
}

// (RDS 6) the same content under another data id - the same file sent again - is rebuilt
// from what is held instead of downloaded: the wanted data's nonce and key give the same
// chunks again, and only chunks that hash to the wanted manifest digest are taken
TEST_CASE("record data store adopts held content", "[unit]") {
	std::string const other_db = "record_data_store_test_b.db";
	std::filesystem::path const other_root = "record_data_store_test_b";
	record_data_store origin{fresh_database(other_db, other_root), other_root};
	record_data_store store{fresh_database(), data_root};
	auto const key = test_group_key();
	std::uint64_t const size = 250000;

	// the same plaintext twice: another nonce, so another data id
	auto const first = write_pattern(origin, key, size, 100000, 7777);
	auto const second = write_pattern(origin, key, size, 100000, 5000);
	REQUIRE(first.descriptor.manifest_digest != second.descriptor.manifest_digest);
	REQUIRE(first.header.content_digest == second.header.content_digest);
	auto const& wanted = second.descriptor;

	// here: the first is held (downloaded and opened once), the second only known
	auto const remote = copy_of(origin, first);
	auto held = store.open({key}, first.descriptor, first.header);
	REQUIRE(held);
	REQUIRE(store.set_manifest(first.descriptor.manifest_digest, remote.manifest));
	CHECK(!store.find_content(first.header.content_digest, wanted.manifest_digest));
	for(auto const& [no, chunk] : remote.chunks) {
		REQUIRE(store.store_chunk(first.descriptor.manifest_digest, no, chunk));
	}
	auto handle = store.open({key}, wanted, second.header);
	REQUIRE(handle);
	CHECK(handle->state() == record_data_state::deferred);

	// the index: a complete data with that content, other than the wanted one
	auto const content = store.find_content(second.header.content_digest, wanted.manifest_digest);
	REQUIRE(content);
	CHECK(content->descriptor == first.descriptor);
	CHECK(content->header == first.header);
	CHECK(!store.find_content(second.header.content_digest, first.descriptor.manifest_digest));
	CHECK(!store.find_content(securepath::test::random_octet_vector(64), wanted.manifest_digest));

	SECTION("rebuilt") {
		CHECK(store.adopt_content(*held, key, wanted, second.header));
		CHECK(handle->state() == record_data_state::in_sync);
		CHECK(handle->available_size() == size);
		CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, size));
		// bit for bit what the author uploaded
		for(std::uint64_t no = 0; no != wanted.chunk_count(); ++no) {
			CHECK(store.read_chunk(wanted.manifest_digest, no) == origin.read_chunk(wanted.manifest_digest, no));
		}
		CHECK(store.manifest(wanted.manifest_digest) == second.manifest);
		CHECK(std::filesystem::is_empty(data_root / ".staging"));
		// both are sources for a third now
		CHECK(store.find_content(second.header.content_digest, securepath::test::random_octet_vector(64)));
	}

	SECTION("a part that was downloaded already is replaced") {
		REQUIRE(store.set_manifest(wanted.manifest_digest, second.manifest));
		REQUIRE(store.store_chunk(wanted.manifest_digest, 1, origin.read_chunk(wanted.manifest_digest, 1).value()));
		CHECK(store.adopt_content(*held, key, wanted, second.header));
		CHECK(handle->state() == record_data_state::in_sync);
		CHECK(read_bytes(*handle, 0, size) == pattern_bytes(0, size));
	}

	SECTION("not the key, not the content") {
		CHECK(!store.adopt_content(*held, test_group_key(), wanted, second.header));
		memory_record_data other{pattern_bytes(1, size)};
		CHECK(!store.adopt_content(other, key, wanted, second.header));
		memory_record_data shorter{pattern_bytes(0, size - 1)};
		CHECK(!store.adopt_content(shorter, key, wanted, second.header));
		CHECK(handle->state() == record_data_state::deferred);
		CHECK(handle->available_size() == 0);
		CHECK(std::filesystem::is_empty(data_root / ".staging"));
	}

	SECTION("an evicted data is no source") {
		held->remove_data();
		CHECK(!store.find_content(second.header.content_digest, wanted.manifest_digest));
	}
}

// (RDS 6) a data table from before the content index gets its columns
TEST_CASE("data state table upgrades", "[unit]") {
	auto db = fresh_database();
	db->prepare("CREATE TABLE record_data("
		"key INTEGER PRIMARY KEY,"
		"data_id BLOB UNIQUE,"
		"enc_size INTEGER,"
		"chunk_size INTEGER,"
		"state INTEGER,"
		"have BLOB,"
		"manifest BLOB);").execute();

	data_state_table table{db};
	data_descriptor const d{5080, 1000, securepath::test::random_octet_vector(64)};
	auto const local_id = table.ensure(d);
	CHECK(!table.header(local_id));
	data_header const header{4500, securepath::test::random_octet_vector(64), securepath::test::random_octet_vector(16), sequence_number{3}, 0};
	table.set_header(local_id, header);
	CHECK(table.header(local_id) == header);
	auto const rows = table.find_by_content(header.content_digest);
	REQUIRE(rows.size() == 1);
	CHECK(rows[0].local_id == local_id);
	CHECK(table.find_by_content(securepath::test::random_octet_vector(64)).empty());
}

}
