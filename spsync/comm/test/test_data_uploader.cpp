#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/comm/data_uploader.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <atomic>
#include <deque>
#include <filesystem>
#include <map>
#include <mutex>
#include <thread>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

std::string const db_name = "data_uploader_test.db";
std::filesystem::path const data_root = "data_uploader_test";

database::connection_ptr fresh_database() {
	std::remove(db_name.c_str());
	std::filesystem::remove_all(data_root);
	return database::sqlite::create_sqlite_connection(db_name);
}

/// a data of the given size in the store, upload_pending as the engine leaves it
data_descriptor create_data(record_data_store& store, std::size_t size, std::uint32_t chunk_size = 1000) {
	encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	auto writer = store.create(key, chunk_size);
	writer.write(securepath::test::random_octet_vector(size));
	return writer.finish().descriptor;
}

/**
 * A holder: keeps what it is sent. Answers inside the call, or - held - when the test
 * releases them, one by one from any thread.
 */
class fake_channel : public data_channel {
public:
	void open_upload(data_descriptor const& d, data_manifest const& m, open_callback cb) override {
		std::unique_lock lock{mutex_};
		opened.push_back(d.manifest_digest);
		if(throw_on_open) {
			throw make_error(securepath::errc::invalid_state, "no connection");
		}
		bool const ok = m.matches(d) && !open_error;
		descriptors[d.manifest_digest] = d;
		auto& have = held.try_emplace(d.manifest_digest, have_bitmap{d.chunk_count()}).first->second;
		util::result<have_bitmap> res = ok ? util::result<have_bitmap>{have}
			: util::result<have_bitmap>{open_error.value_or(make_error(securepath::errc::invalid_data))};
		answer(lock, [cb = std::move(cb), res = std::move(res)]() mutable { cb(std::move(res)); });
	}

	void send_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, octet_vector bytes, piece_callback cb) override {
		std::unique_lock lock{mutex_};
		if(offset == 0) {
			sent.emplace_back(id, chunk_no);
		}
		pieces.push_back(piece{id, chunk_no, offset, bytes.size()});
		auto& out = outstanding[id];
		++out;
		max_outstanding = std::max(max_outstanding, out);
		std::optional<error> err;
		if(fail_chunk && *fail_chunk == chunk_no) {
			err = make_error(securepath::errc::invalid_data, "refused");
		} else {
			// as the data server takes them: a piece at offset 0 starts the chunk over
			auto& arrived = arriving[id][chunk_no];
			arrived = offset == 0 ? 0 : arrived;
			if(bytes.empty() || offset != arrived) {
				err = make_error(securepath::errc::invalid_data, "not the next piece of the chunk");
			} else {
				arrived += bytes.size();
			}
		}
		answer(lock, [this, id, chunk_no, err, cb = std::move(cb)]() mutable {
			{
				std::unique_lock l{mutex_};
				--outstanding[id];
				// the chunk is held when its last piece was taken
				if(!err && arriving[id][chunk_no] == descriptors.at(id).chunk_enc_size(chunk_no)) {
					held.at(id).set(chunk_no);
				}
			}
			cb(err);
		});
	}

	/// deliver held answers; returns how many were delivered
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

	/// the connection went: the held answers are never delivered
	std::size_t drop() {
		std::unique_lock lock{mutex_};
		std::size_t const n = answers_.size();
		answers_.clear();
		return n;
	}

	std::size_t sent_count() const {
		std::unique_lock lock{mutex_};
		return sent.size();
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
	std::atomic<bool> hold{false};
	bool throw_on_open{};
	std::optional<error> open_error;
	std::optional<std::uint64_t> fail_chunk;

	struct piece {
		data_id id;
		std::uint64_t chunk_no{};
		std::uint64_t offset{};
		std::size_t size{};
	};

	std::map<data_id, have_bitmap> held;
	std::map<data_id, data_descriptor> descriptors;
	/// octets taken of a chunk so far
	std::map<data_id, std::map<std::uint64_t, std::uint64_t>> arriving;
	std::vector<data_id> opened;
	/// the chunks that were started, in order (a piece at offset 0)
	std::vector<std::pair<data_id, std::uint64_t>> sent;
	std::vector<piece> pieces;
	std::map<data_id, std::size_t> outstanding;
	std::size_t max_outstanding{};

private:
	mutable std::mutex mutex_;
	std::deque<std::move_only_function<void()>> answers_;
};

/// what the uploader reported
struct upload_log {
	data_uploader::done_callback done() {
		return [this](data_id const& id, std::optional<error> err) {
			std::unique_lock lock{mutex};
			finished.emplace_back(id, std::move(err));
		};
	}

	data_uploader::progress_callback progress() {
		return [this](data_id const& id, std::uint64_t transferred, std::uint64_t total) {
			std::unique_lock lock{mutex};
			reports[id].emplace_back(transferred, total);
		};
	}

	std::size_t finished_count() const {
		std::unique_lock lock{mutex};
		return finished.size();
	}

	mutable std::mutex mutex;
	std::vector<std::pair<data_id, std::optional<error>>> finished;
	std::map<data_id, std::vector<std::pair<std::uint64_t, std::uint64_t>>> reports;
};

}

// RD7: commit order, a few datas at a time, a window of chunks each
TEST_CASE("data uploader uploads in queue order", "[unit]") {
	record_data_store store{fresh_database(), data_root};
	auto const a = create_data(store, 4500);
	auto const b = create_data(store, 9000);
	auto const c = create_data(store, 100);
	REQUIRE(a.chunk_count() == 5);

	fake_channel channel;
	channel.hold = true;
	upload_log log;
	data_uploader uploader{store, channel, data_upload_config{2, 3}, log.done(), log.progress()};

	CHECK(uploader.enqueue(a.manifest_digest));
	CHECK(uploader.enqueue(b.manifest_digest));
	CHECK(uploader.enqueue(c.manifest_digest));
	CHECK(!uploader.enqueue(a.manifest_digest));
	CHECK(!uploader.enqueue(c.manifest_digest));

	// two on their way, the third waits; nothing is sent before the holder answered the manifest
	CHECK(channel.opened == std::vector<data_id>{a.manifest_digest, b.manifest_digest});
	CHECK(uploader.in_flight() == 2);
	CHECK(uploader.queued() == 1);
	CHECK(channel.sent.empty());

	// the manifests answered: a window of chunks each
	CHECK(channel.release(2) == 2);
	CHECK(channel.sent.size() == 6);
	CHECK(channel.outstanding[a.manifest_digest] == 3);
	CHECK(channel.outstanding[b.manifest_digest] == 3);

	// an answered chunk makes room for the next one
	CHECK(channel.release(1) == 1);
	CHECK(channel.sent.size() == 7);

	while(channel.release(1) != 0) {
		CHECK(uploader.in_flight() <= 2);
	}
	CHECK(channel.max_outstanding == 3);
	CHECK(channel.opened == std::vector<data_id>{a.manifest_digest, b.manifest_digest, c.manifest_digest});
	CHECK(uploader.in_flight() == 0);
	CHECK(uploader.queued() == 0);

	REQUIRE(log.finished.size() == 3);
	CHECK(log.finished[0].first == a.manifest_digest);
	for(auto const& f : log.finished) {
		CHECK(!f.second);
	}
	for(auto const& d : {a, b, c}) {
		CHECK(channel.held.at(d.manifest_digest).complete());
		REQUIRE(!log.reports[d.manifest_digest].empty());
		CHECK(log.reports[d.manifest_digest].front() == std::pair<std::uint64_t, std::uint64_t>{0, d.enc_size});
		CHECK(log.reports[d.manifest_digest].back() == std::pair{d.enc_size, d.enc_size});
	}
	CHECK(channel.sent.size() == a.chunk_count() + b.chunk_count() + c.chunk_count());

	// done is done: it can be queued again (and the holder has everything)
	CHECK(uploader.enqueue(a.manifest_digest));
	channel.release();
	CHECK(log.finished.size() == 4);
	CHECK(channel.sent.size() == a.chunk_count() + b.chunk_count() + c.chunk_count());
}

// RD4: the holder's answer to the manifest says what is left
TEST_CASE("data uploader resumes from what the holder has", "[unit]") {
	record_data_store store{fresh_database(), data_root};
	auto const a = create_data(store, 4500);
	auto const& id = a.manifest_digest;

	fake_channel channel;
	have_bitmap have{a.chunk_count()};
	have.set(0);
	have.set(2);
	channel.held[id] = have;

	upload_log log;
	data_uploader uploader{store, channel, data_upload_config{}, log.done(), log.progress()};
	CHECK(uploader.enqueue(id));

	CHECK(channel.sent == std::vector<std::pair<data_id, std::uint64_t>>{{id, 1}, {id, 3}, {id, 4}});
	REQUIRE(log.finished.size() == 1);
	CHECK(!log.finished[0].second);
	// progress starts from what the holder had
	CHECK(log.reports[id].front().first == a.chunk_enc_size(0) + a.chunk_enc_size(2));
	CHECK(log.reports[id].back().first == a.enc_size);
}

// the connection goes in the middle: nothing is reported, the next try sends the rest only
TEST_CASE("data uploader interrupted upload", "[unit]") {
	record_data_store store{fresh_database(), data_root};
	auto const a = create_data(store, 9500);
	auto const& id = a.manifest_digest;
	REQUIRE(a.chunk_count() == 10);

	fake_channel channel;
	channel.hold = true;
	upload_log log;
	data_uploader uploader{store, channel, data_upload_config{2, 4}, log.done()};

	CHECK(uploader.enqueue(id));
	// the manifest and two chunks answered, four more chunks on their way
	CHECK(channel.release(3) == 3);
	CHECK(channel.held.at(id).count() == 2);
	CHECK(channel.sent.size() == 6);

	uploader.reset();
	CHECK(uploader.in_flight() == 0);
	CHECK(uploader.queued() == 0);

	// of the chunks on their way two made it to the holder, two were lost with the
	// connection; the answers say nothing any more
	CHECK(channel.release(2) == 2);
	CHECK(channel.drop() == 2);
	CHECK(log.finished.empty());
	CHECK(channel.sent.size() == 6);
	auto const held_before = channel.held.at(id).count();
	CHECK(held_before == 4);

	// after the reconnect the owner queues it again
	CHECK(uploader.enqueue(id));
	channel.release();
	REQUIRE(log.finished.size() == 1);
	CHECK(!log.finished[0].second);
	CHECK(channel.held.at(id).complete());
	CHECK(channel.sent.size() == 6 + (a.chunk_count() - held_before));
}

TEST_CASE("data uploader errors", "[unit]") {
	record_data_store store{fresh_database(), data_root};
	auto const a = create_data(store, 9500);
	auto const b = create_data(store, 100);
	auto const& id = a.manifest_digest;

	fake_channel channel;
	upload_log log;
	data_uploader uploader{store, channel, data_upload_config{2, 3}, log.done()};

	SECTION("the holder refuses the manifest") {
		channel.open_error = make_error(securepath::errc::constraint_violation, "quota exceeded");
		CHECK(uploader.enqueue(id));
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(securepath::errc::constraint_violation));
		CHECK(channel.sent.empty());
	}

	SECTION("the channel throws") {
		channel.throw_on_open = true;
		CHECK(uploader.enqueue(id));
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(securepath::errc::invalid_state));
	}

	SECTION("a chunk is refused") {
		channel.hold = true;
		channel.fail_chunk = 0;
		CHECK(uploader.enqueue(id));
		channel.release();
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		// the window that was out is all that was sent
		CHECK(channel.sent.size() == 3);
		CHECK(uploader.in_flight() == 0);

		// the next data is not held up by it
		channel.fail_chunk.reset();
		CHECK(uploader.enqueue(b.manifest_digest));
		channel.release();
		REQUIRE(log.finished.size() == 2);
		CHECK(!log.finished[1].second);
	}

	SECTION("a data the store does not hold") {
		CHECK(uploader.enqueue(securepath::test::random_octet_vector(64)));
		REQUIRE(log.finished.size() == 1);
		REQUIRE(log.finished[0].second);
		CHECK(log.finished[0].second->code() == make_error_code(securepath::errc::no_such_data));
		CHECK(channel.opened.empty());

		// evicted chunks cannot be sent
		store.set_state(id, record_data_state::in_sync);
		REQUIRE(store.evict(id));
		CHECK(uploader.enqueue(id));
		REQUIRE(log.finished.size() == 2);
		REQUIRE(log.finished[1].second);
		CHECK(log.finished[1].second->code() == make_error_code(securepath::errc::no_such_data));
	}
}

// a chunk travels in pieces read from its file: in order, a window of pieces out at once,
// so what is in memory and on the way does not grow with the chunk size
TEST_CASE("data uploader sends chunks in pieces", "[unit]") {
	record_data_store store{fresh_database(), data_root};
	auto const a = create_data(store, 4500);
	auto const& id = a.manifest_digest;
	REQUIRE(a.chunk_count() == 5);

	fake_channel channel;
	channel.hold = true;
	upload_log log;
	// a chunk of 1016 octets in pieces of 300: 300, 300, 300, 116
	data_uploader uploader{store, channel, data_upload_config{2, 3, 300}, log.done(), log.progress()};
	CHECK(uploader.enqueue(id));
	CHECK(channel.release(1) == 1);

	// the window counts pieces, not chunks
	REQUIRE(channel.pieces.size() == 3);
	CHECK(channel.max_outstanding == 3);
	for(std::size_t i = 0; i != 3; ++i) {
		CHECK(channel.pieces[i].chunk_no == 0);
		CHECK(channel.pieces[i].offset == i * 300);
		CHECK(channel.pieces[i].size == 300);
	}
	CHECK(channel.held.at(id).count() == 0);

	channel.release();
	REQUIRE(log.finished.size() == 1);
	CHECK(!log.finished[0].second);
	CHECK(channel.max_outstanding == 3);
	CHECK(channel.held.at(id).complete());

	// every chunk in order from offset 0 in pieces of 300, the last piece of a chunk is
	// what is left of it (the last chunk of the data is a short one)
	std::vector<fake_channel::piece> expected;
	for(std::uint64_t no = 0; no != a.chunk_count(); ++no) {
		for(std::uint64_t offset = 0; offset < a.chunk_enc_size(no); offset += 300) {
			expected.push_back({id, no, offset, static_cast<std::size_t>(std::min<std::uint64_t>(300, a.chunk_enc_size(no) - offset))});
		}
	}
	REQUIRE(channel.pieces.size() == expected.size());
	std::uint64_t total = 0;
	for(std::size_t i = 0; i != expected.size(); ++i) {
		auto const& p = channel.pieces[i];
		CHECK(p.chunk_no == expected[i].chunk_no);
		CHECK(p.offset == expected[i].offset);
		CHECK(p.size == expected[i].size);
		total += p.size;
	}
	CHECK(total == a.enc_size);

	// progress moves with every piece
	auto const& reports = log.reports[id];
	REQUIRE(reports.size() == 1 + expected.size());
	CHECK(reports[1].first == 300);
	CHECK(reports.back().first == a.enc_size);
}

// a channel answering inside the call must not nest rounds without end
TEST_CASE("data uploader with a channel answering at once", "[unit]") {
	record_data_store store{fresh_database(), data_root};
	auto const a = create_data(store, 300000, 500);
	REQUIRE(a.chunk_count() > 500);

	fake_channel channel;
	upload_log log;
	data_uploader uploader{store, channel, data_upload_config{}, log.done()};
	CHECK(uploader.enqueue(a.manifest_digest));
	REQUIRE(log.finished.size() == 1);
	CHECK(!log.finished[0].second);
	CHECK(channel.held.at(a.manifest_digest).complete());
	CHECK(channel.sent.size() == a.chunk_count());
}

// answers from another thread while datas are queued
TEST_CASE("data uploader with answers from another thread", "[unit]") {
	record_data_store store{fresh_database(), data_root};
	std::vector<data_descriptor> datas;
	for(int i = 0; i != 6; ++i) {
		datas.push_back(create_data(store, 20000));
	}

	fake_channel channel;
	channel.hold = true;
	upload_log log;
	data_uploader uploader{store, channel, data_upload_config{2, 4}, log.done(), log.progress()};

	std::atomic<bool> stop{false};
	std::jthread answering{[&] {
		while(!stop) {
			if(channel.release(1) == 0) {
				std::this_thread::sleep_for(1ms);
			}
		}
	}};
	for(auto const& d : datas) {
		CHECK(uploader.enqueue(d.manifest_digest));
	}
	WAIT_CHECK(log.finished_count() == datas.size(), 10s);
	stop = true;
	answering.join();

	std::uint64_t chunks = 0;
	for(auto const& d : datas) {
		CHECK(channel.held.at(d.manifest_digest).complete());
		chunks += d.chunk_count();
	}
	CHECK(channel.sent_count() == chunks);
	CHECK(channel.max_outstanding <= 4);
	for(auto const& f : log.finished) {
		CHECK(!f.second);
	}
}

}
