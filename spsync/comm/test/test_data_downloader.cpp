#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <spsync/test/test_record_data.hpp>

#include <spsync/comm/data_downloader.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <atomic>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

encryption_key const& test_key() {
	static encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	return key;
}

/// a store of its own database and chunk directory
struct test_store {
	explicit test_store(std::string const& name)
	: root("data_downloader_test_" + name)
	, store((clean(name), database::sqlite::create_sqlite_connection(root.string() + ".db")), root)
	{}

	static void clean(std::string const& name) {
		std::filesystem::path const root = "data_downloader_test_" + name;
		std::filesystem::remove_all(root);
		std::remove((root.string() + ".db").c_str());
	}

	std::filesystem::path root;
	record_data_store store;
};

/// what the author made under the shared key: both descriptor halves, the plaintext
test::stored_data make_data(record_data_store& origin, std::size_t size, std::uint32_t chunk_size = 1000) {
	return test::store_data(origin, size, chunk_size, test_key());
}

/// a holder serving out of the origin store; what it has of a data can be cut down
class fake_holder : public data_download_channel {
public:
	explicit fake_holder(record_data_store& origin)
	: origin_(origin)
	{}

	void open_download(data_descriptor const& d, download_callback cb) override {
		std::unique_lock lock{mutex_};
		opened.push_back(d.manifest_digest);
		util::result<download_info> res{make_error(protocol::errc::data_not_held)};
		auto const manifest = origin_.manifest(d.manifest_digest);
		if(open_error) {
			res = *open_error;
		} else if(manifest) {
			have_bitmap have{d.chunk_count()};
			for(std::uint64_t no = 0; no != d.chunk_count(); ++no) {
				have.set(no, !missing.contains(no));
			}
			res = download_info{forged_manifest.value_or(*manifest), have};
		}
		answer(lock, [cb = std::move(cb), res = std::move(res)]() mutable { cb(std::move(res)); });
	}

	void fetch_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size, fetch_callback cb) override {
		std::unique_lock lock{mutex_};
		pieces.push_back(piece{chunk_no, offset, size});
		auto& out = outstanding;
		++out;
		max_outstanding = std::max(max_outstanding, out);
		util::result<octet_vector> res{make_error(protocol::errc::data_not_held)};
		auto bytes = missing.contains(chunk_no) ? std::nullopt : origin_.read_chunk_piece(id, chunk_no, offset, size);
		if(fail_after && pieces.size() > *fail_after) {
			res = make_error(protocol::errc::data_transfer_quota_exceeded);
		} else if(bytes) {
			if(corrupt_chunk && *corrupt_chunk == chunk_no && offset == 0) {
				(*bytes)[0] ^= 0x01;
			}
			res = std::move(*bytes);
		}
		answer(lock, [this, cb = std::move(cb), res = std::move(res)]() mutable {
			{
				std::unique_lock l{mutex_};
				--outstanding;
			}
			cb(std::move(res));
		});
	}

	std::size_t release(std::size_t max = std::numeric_limits<std::size_t>::max()) {
		std::size_t n = 0;
		bool more = true;
		while(more && n != max) {
			std::move_only_function<void()> next;
			{
				std::unique_lock lock{mutex_};
				more = !answers_.empty();
				if(more) {
					next = std::move(answers_.front());
					answers_.pop_front();
				}
			}
			if(more) {
				next();
				++n;
			}
		}
		return n;
	}

private:
	void answer(std::unique_lock<std::mutex>& lock, std::move_only_function<void()> f) {
		if(hold) {
			answers_.push_back(std::move(f));
		} else {
			lock.unlock();
			f();
		}
	}

public:
	struct piece {
		std::uint64_t chunk_no{};
		std::uint64_t offset{};
		std::uint32_t size{};
	};

	bool hold{};
	/// chunks the holder does not have (an upload in progress)
	std::set<std::uint64_t> missing;
	std::optional<error> open_error;
	std::optional<data_manifest> forged_manifest;
	std::optional<std::uint64_t> corrupt_chunk;
	/// every piece after this many is refused
	std::optional<std::size_t> fail_after;

	std::vector<data_id> opened;
	std::vector<piece> pieces;
	std::size_t outstanding{};
	std::size_t max_outstanding{};

private:
	record_data_store& origin_;
	std::mutex mutex_;
	std::deque<std::move_only_function<void()>> answers_;
};

using download_log = test::transfer_log;
using test::read_all;

}

// RD4/RD7: manifest first, then the missing chunks in pieces, each verified when whole
TEST_CASE("data downloader fetches a data", "[unit]") {
	test_store origin{"origin"};
	test_store local{"local"};
	auto const data = make_data(origin.store, 4500);
	auto const& d = data.result.descriptor;
	auto const& id = d.manifest_digest;

	// the record named the data: known here, nothing held
	auto handle = local.store.open({test_key()}, d, data.result.header);
	REQUIRE(handle);
	CHECK(handle->state() == record_data_state::deferred);

	fake_holder holder{origin.store};
	holder.hold = true;
	download_log log;
	data_downloader downloader{local.store, holder, data_download_config{2, 3, 300}, log.done(), log.progress()};

	CHECK(downloader.enqueue(id));
	CHECK(!downloader.enqueue(id));
	CHECK(holder.opened == std::vector<data_id>{id});
	CHECK(holder.pieces.empty());

	// the opening answered: the manifest is kept, a window of pieces is asked for
	CHECK(holder.release(1) == 1);
	CHECK(local.store.manifest(id) == data.result.manifest);
	REQUIRE(holder.pieces.size() == 3);
	for(std::size_t i = 0; i != 3; ++i) {
		CHECK(holder.pieces[i].chunk_no == 0);
		CHECK(holder.pieces[i].offset == i * 300);
	}

	holder.release();
	CHECK(holder.max_outstanding == 3);
	REQUIRE(log.finished.size() == 1);
	CHECK(!log.finished[0].second);
	CHECK(downloader.in_flight() == 0);

	// every chunk in order from offset 0, the sizes add up to the data
	std::uint64_t total = 0;
	std::uint64_t expected_offset = 0;
	std::uint64_t chunk = 0;
	for(auto const& p : holder.pieces) {
		if(p.chunk_no != chunk) {
			CHECK(p.chunk_no == chunk + 1);
			chunk = p.chunk_no;
			expected_offset = 0;
		}
		CHECK(p.offset == expected_offset);
		expected_offset += p.size;
		total += p.size;
	}
	CHECK(total == d.enc_size);
	CHECK(log.reports.front().transferred == 0);
	CHECK(log.reports.back().transferred == d.enc_size);

	// the store flipped the state with the last chunk; it reads as what was written
	CHECK(handle->state() == record_data_state::in_sync);
	CHECK(read_all(*handle) == data.plain);
	CHECK(std::filesystem::is_empty(local.root / ".staging"));

	// held: asking again moves nothing
	auto const asked = holder.pieces.size();
	CHECK(downloader.enqueue(id));
	holder.release();
	CHECK(log.finished.size() == 2);
	CHECK(!log.finished[1].second);
	CHECK(holder.pieces.size() == asked);
}

// RD7 remote_not_complete: the holder has a part while the upload is in progress; what it
// has is kept, the rest comes with the next fetch
TEST_CASE("data downloader with a holder that has a part", "[unit]") {
	test_store origin{"origin"};
	test_store local{"local"};
	auto const data = make_data(origin.store, 4500);
	auto const& d = data.result.descriptor;
	auto const& id = d.manifest_digest;
	auto handle = local.store.open({test_key()}, d, data.result.header);

	fake_holder holder{origin.store};
	holder.missing = {1, 4};
	download_log log;
	data_downloader downloader{local.store, holder, data_download_config{}, log.done(), log.progress()};

	CHECK(downloader.enqueue(id));
	REQUIRE(log.finished.size() == 1);
	CHECK(log.ended_with(0, protocol::errc::data_not_held));
	auto const row = local.store.find(id);
	CHECK(row->have.count() == 3);
	CHECK(!row->have.test(1));
	CHECK(row->state != record_data_state::in_sync);
	CHECK(handle->available_size() == 3000);

	// the upload completed over there
	holder.missing.clear();
	auto const asked_before = holder.pieces.size();
	CHECK(downloader.enqueue(id));
	REQUIRE(log.finished.size() == 2);
	CHECK(!log.finished[1].second);
	// only the two chunks that were missing moved
	CHECK(holder.pieces.size() == asked_before + 2);
	CHECK(handle->state() == record_data_state::in_sync);
	CHECK(read_all(*handle) == data.plain);
	// progress went on from what was held
	CHECK(log.reports.back().transferred == d.enc_size);
}

// what stops a download keeps the whole chunks: the next one goes on from there
TEST_CASE("data downloader stopped half way", "[unit]") {
	test_store origin{"origin"};
	test_store local{"local"};
	auto const data = make_data(origin.store, 9500);
	auto const& d = data.result.descriptor;
	auto const& id = d.manifest_digest;
	REQUIRE(d.chunk_count() == 10);
	auto handle = local.store.open({test_key()}, d, data.result.header);

	fake_holder holder{origin.store};
	download_log log;

	SECTION("the local store fails") {
		// (review 2026-09-21) the staging area is gone under the download's feet, so the
		// next piece cannot be written: the download ends with that error - it used to
		// escape into whoever delivered the answer (over the network: the link's packet
		// handler, which closed the link every transfer shares) and skip the bookkeeping
		holder.hold = true;
		data_downloader downloader{local.store, holder, data_download_config{2, 1, 600}, log.done()};
		CHECK(downloader.enqueue(id));
		// the open is answered, the first piece is asked for
		CHECK(holder.release(1) == 1);
		std::filesystem::remove_all(local.root / ".staging");
		{ std::ofstream in_the_way{local.root / ".staging"}; }
		CHECK_NOTHROW(holder.release());
		REQUIRE(log.finished.size() == 1);
		CHECK(log.finished[0].second.has_value());
		CHECK(downloader.in_flight() == 0);

		// and the queue works on: the same data again, from a store that is whole
		std::filesystem::remove(local.root / ".staging");
		std::filesystem::create_directories(local.root / ".staging");
		holder.hold = false;
		CHECK(downloader.enqueue(id));
		REQUIRE(log.finished.size() == 2);
		CHECK(!log.finished[1].second);
		CHECK(read_all(*handle) == data.plain);
	}

	SECTION("a transfer quota") {
		// four pieces of 600: two whole chunks of 1016, then the refusal
		holder.fail_after = 4;
		data_downloader downloader{local.store, holder, data_download_config{2, 1, 600}, log.done()};
		CHECK(downloader.enqueue(id));
		REQUIRE(log.finished.size() == 1);
		CHECK(log.ended_with(0, protocol::errc::data_transfer_quota_exceeded));
		CHECK(local.store.find(id)->have.count() == 2);
		CHECK(std::filesystem::is_empty(local.root / ".staging"));

		// the next window
		holder.fail_after.reset();
		CHECK(downloader.enqueue(id));
		REQUIRE(log.finished.size() == 2);
		CHECK(!log.finished[1].second);
		CHECK(read_all(*handle) == data.plain);
	}

	SECTION("a lost connection") {
		holder.hold = true;
		data_downloader downloader{local.store, holder, data_download_config{2, 4, 600}, log.done()};
		CHECK(downloader.enqueue(id));
		// the opening and three pieces: one whole chunk and half of the next
		CHECK(holder.release(4) == 4);
		CHECK(local.store.find(id)->have.count() == 1);
		CHECK(!std::filesystem::is_empty(local.root / ".staging"));

		downloader.reset();
		CHECK(downloader.in_flight() == 0);
		// the half chunk went, the whole one stays; late answers say nothing any more
		CHECK(std::filesystem::is_empty(local.root / ".staging"));
		holder.release();
		CHECK(log.finished.empty());
		CHECK(local.store.find(id)->have.count() == 1);

		holder.hold = false;
		CHECK(downloader.enqueue(id));
		REQUIRE(log.finished.size() == 1);
		CHECK(!log.finished[0].second);
		CHECK(read_all(*handle) == data.plain);
	}
}

// verification on fetch: nothing is kept that is not what the record commits to
TEST_CASE("data downloader verification", "[unit]") {
	test_store origin{"origin"};
	test_store local{"local"};
	auto const data = make_data(origin.store, 4500);
	auto const& d = data.result.descriptor;
	auto const& id = d.manifest_digest;
	auto handle = local.store.open({test_key()}, d, data.result.header);

	fake_holder holder{origin.store};
	download_log log;
	data_downloader downloader{local.store, holder, data_download_config{}, log.done()};

	SECTION("a manifest that is not the descriptor's") {
		auto forged = data.result.manifest;
		forged.chunk_digests[0] = securepath::test::random_octet_vector(64);
		holder.forged_manifest = forged;
		CHECK(downloader.enqueue(id));
		REQUIRE(log.finished.size() == 1);
		CHECK(log.ended_with(0, protocol::errc::invalid_data_manifest));
		CHECK(holder.pieces.empty());
		CHECK(!local.store.manifest(id));
	}

	SECTION("a chunk that is not the manifest's") {
		holder.corrupt_chunk = 2;
		CHECK(downloader.enqueue(id));
		REQUIRE(log.finished.size() == 1);
		CHECK(log.ended_with(0, protocol::errc::invalid_data_chunk));
		auto const row = local.store.find(id);
		CHECK(!row->have.test(2));
		CHECK(row->have.test(0));
		CHECK(std::filesystem::is_empty(local.root / ".staging"));
	}

	SECTION("the holder refuses") {
		holder.open_error = make_error(protocol::errc::data_ticket_expired);
		CHECK(downloader.enqueue(id));
		REQUIRE(log.finished.size() == 1);
		CHECK(log.ended_with(0, protocol::errc::data_ticket_expired));
	}

	SECTION("a data no record named") {
		CHECK(downloader.enqueue(securepath::test::random_octet_vector(64)));
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(securepath::errc::no_such_data));
		CHECK(holder.opened.empty());
	}
}

// queue order, a few at a time
TEST_CASE("data downloader queue", "[unit]") {
	test_store origin{"origin"};
	test_store local{"local"};
	std::vector<test::stored_data> datas;
	for(int i = 0; i != 4; ++i) {
		datas.push_back(make_data(origin.store, 2500));
		REQUIRE(local.store.open({test_key()}, datas.back().result.descriptor, datas.back().result.header));
	}

	fake_holder holder{origin.store};
	holder.hold = true;
	download_log log;
	data_downloader downloader{local.store, holder, data_download_config{2, 4, 128 * 1024}, log.done()};
	for(auto const& data : datas) {
		CHECK(downloader.enqueue(data.result.descriptor.manifest_digest));
	}
	CHECK(holder.opened.size() == 2);
	CHECK(downloader.in_flight() == 2);
	CHECK(downloader.queued() == 2);

	while(holder.release(1) != 0) {
		CHECK(downloader.in_flight() <= 2);
	}
	REQUIRE(log.finished.size() == 4);
	for(std::size_t i = 0; i != 4; ++i) {
		CHECK(holder.opened[i] == datas[i].result.descriptor.manifest_digest);
		CHECK(!log.finished[i].second);
		CHECK(local.store.find(datas[i].result.descriptor.manifest_digest)->state == record_data_state::in_sync);
	}
}

}
