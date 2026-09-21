#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/comm/data_channel.hpp>
#include <spsync/comm/net_connection.hpp>
#include <spsync/core/data/record_data_store.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/protocol/error.hpp>

#include <spsync/test/test_context.hpp>
#include <spsync/test/util.hpp>

#include <securepath/crypto/aes_gcm.hpp>

#include <atomic>
#include <filesystem>
#include <mutex>
#include <thread>

namespace securepath::sync::client::test {
namespace {

using namespace std::chrono_literals;

/// a holder that takes everything
struct accepting_channel : data_channel {
	void open_upload(data_descriptor const& d, data_manifest const&, open_callback cb) override {
		cb(util::result<have_bitmap>{have_bitmap{d.chunk_count()}});
	}

	void send_piece(data_id const&, std::uint64_t, std::uint64_t, octet_vector, piece_callback cb) override {
		++chunks;
		cb(std::nullopt);
	}

	std::atomic<std::uint64_t> chunks{0};
};

/// the engine's side of comm, as far as uploads go
struct upload_output : comm_output {
	using comm_output::comm_output;
	~upload_output() { stop_handler(); }

	void on_connected() override {}
	void on_disconnected(std::optional<error>) override {}
	void on_sequence_number_response(request_handle, result<sequence_info> const&) override {}
	void on_record_response(request_handle, record_response const&) override {}
	void on_data_downloaded(request_handle h, std::optional<error> err) override {
		std::unique_lock lock{mutex};
		downloads.emplace_back(h, std::move(err));
		++downloaded;
	}
	void on_commit_response(request_handle, commit_response const&) override {}
	void on_record_received(chain_block const&, std::optional<block_envelope> const&) override {}

	void on_data_uploaded(request_handle h, std::optional<error> err) override {
		std::unique_lock lock{mutex};
		answers.emplace_back(h, std::move(err));
		++answered;
	}

	std::atomic<int> answered{0};
	std::atomic<int> downloaded{0};
	std::mutex mutex;
	std::vector<std::pair<request_handle, std::optional<error>>> answers;
	std::vector<std::pair<request_handle, std::optional<error>>> downloads;
};

/// a holder whose connection drops a few times before it takes everything
struct flaky_channel : accepting_channel {
	void open_upload(data_descriptor const& d, data_manifest const& m, open_callback cb) override {
		++opens;
		if(opens <= failures) {
			cb(util::result<have_bitmap>{failure});
		} else {
			accepting_channel::open_upload(d, m, std::move(cb));
		}
	}

	std::atomic<int> opens{0};
	int failures{1};
	error failure{make_error(securepath::errc::invalid_state, "data connection closed")};
};

/// serves a data out of another store; the first pieces run into a transfer quota
struct quota_holder : data_download_channel {
	explicit quota_holder(record_data_store& origin) : origin(origin) {}

	void open_download(data_descriptor const& d, download_callback cb) override {
		++opens;
		have_bitmap have{d.chunk_count()};
		have.set_all();
		cb(util::result<download_info>{download_info{origin.manifest(d.manifest_digest).value(), have}});
	}

	void fetch_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size, fetch_callback cb) override {
		if(refusals-- > 0) {
			cb(util::result<octet_vector>{protocol::make_retry_error(protocol::errc::data_transfer_quota_exceeded, 1)});
		} else {
			cb(util::result<octet_vector>{origin.read_chunk_piece(id, chunk_no, offset, size).value()});
		}
	}

	record_data_store& origin;
	std::atomic<int> opens{0};
	std::atomic<int> refusals{1};
};

struct upload_progress : sync::progress {
	using progress::progress;
	~upload_progress() { stop_handler(); }

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch(*ev, event_dest<progress_events::on_data_progress>(&upload_progress::on_data_progress));
	}

	void on_data_progress(data_id, std::uint64_t transferred, std::uint64_t total, bool upload) {
		last_transferred = transferred;
		last_total = total;
		uploads += upload ? 1 : 0;
	}

	std::atomic<std::uint64_t> last_transferred{0};
	std::atomic<std::uint64_t> last_total{0};
	std::atomic<int> uploads{0};
};

struct null_handler : event_system::event_handler {
	using event_handler::event_handler;
	~null_handler() { stop_handler(); }
	void handle_event(std::unique_ptr<event_system::event_base>) override {}
};

data_descriptor create_data(record_data_store& store, std::size_t size) {
	encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
	auto writer = store.create(key, 1000);
	writer.write(securepath::test::random_octet_vector(size));
	return writer.finish().descriptor;
}

}

// (RDS 3) comm::upload_data: the uploader behind the storage connection, the answer as
// on_data_uploaded on the output's loop, progress on the progress handler
TEST_CASE("comm upload data", "[unit]") {
	event_system::single_thread_event_loop loop;
	sync::test::test_context net_context;
	net_context.add_client(1);

	std::filesystem::remove_all("comm_upload_test");
	auto db = sync::test::create_test_database("comm_upload_test.db");
	record_storage storage{db};
	record_data_store store{db, "comm_upload_test"};
	auto const data = create_data(store, 4500);

	null_handler handler{loop};
	upload_progress progress{loop};
	upload_output output{loop};
	accepting_channel channel;
	network_connection net{net_context.client_context(0), handler};

	SECTION("with a data channel") {
		auto sconn = net.create_storage_connection(octet_vector(16, 1), storage, progress, {}, &store, &channel);
		sconn.attach(output);
		CHECK(sconn.input().data() == &store);

		auto const h = sconn.input().upload_data(data.manifest_digest);
		WAIT_CHECK(output.answered == 1, 2s);
		REQUIRE(output.answers.size() == 1);
		CHECK(output.answers[0].first == h);
		CHECK(!output.answers[0].second);
		CHECK(channel.chunks == data.chunk_count());
		WAIT_CHECK(progress.last_transferred == data.enc_size, 2s);
		CHECK(progress.last_total == data.enc_size);
		CHECK(progress.uploads > 0);
		net.detach(octet_vector(16, 1));
	}

	SECTION("a storage without record data") {
		auto sconn = net.create_storage_connection(octet_vector(16, 3), storage, progress);
		sconn.attach(output);
		CHECK(sconn.input().data() == nullptr);
		sconn.input().upload_data(data.manifest_digest);
		WAIT_CHECK(output.answered == 1, 2s);
		REQUIRE(output.answers.size() == 1);
		REQUIRE(output.answers[0].second);
		CHECK(output.answers[0].second->code() == make_error_code(securepath::errc::not_supported));
		net.detach(octet_vector(16, 3));
	}

	SECTION("the real channel is made when none is given") {
		// (RDS 5) its tickets come over the record connection: not connected here, so the
		// request waits - and is answered when the storage connection goes away
		auto sconn = net.create_storage_connection(octet_vector(16, 2), storage, progress, {}, &store);
		sconn.attach(output);
		sconn.input().upload_data(data.manifest_digest);
		std::this_thread::sleep_for(200ms);
		CHECK(output.answered == 0);
		CHECK(channel.chunks == 0);
		net.detach(octet_vector(16, 2));
	}
}

// (RDS 7) a transfer that ended with an error another try may lift is tried again by comm
// after a wait - the record connection is fine, nobody has to reconnect - and the owner
// hears of it once, when it ended for good
TEST_CASE("comm retries transfers", "[unit]") {
	event_system::single_thread_event_loop loop;
	sync::test::test_context net_context;
	net_context.add_client(1);

	std::filesystem::remove_all("comm_upload_test");
	std::filesystem::remove_all("comm_upload_test_origin");
	auto db = sync::test::create_test_database("comm_upload_test.db");
	record_storage storage{db};
	record_data_store store{db, "comm_upload_test"};

	null_handler handler{loop};
	upload_progress progress{loop};
	upload_output output{loop};
	network_connection net{net_context.client_context(0), handler};
	auto const sid = octet_vector(16, 7);

	SECTION("an upload whose data connection dropped") {
		auto const data = create_data(store, 4500);
		flaky_channel channel;
		auto sconn = net.create_storage_connection(sid, storage, progress, {}, &store, &channel);
		sconn.attach(output);
		auto const h = sconn.input().upload_data(data.manifest_digest);

		// nothing is reported while it is tried again...
		std::this_thread::sleep_for(300ms);
		CHECK(output.answered == 0);
		CHECK(channel.opens == 1);
		// ...and once when it is through
		WAIT_CHECK(output.answered == 1, 5s);
		REQUIRE(output.answers.size() == 1);
		CHECK(output.answers[0].first == h);
		CHECK(!output.answers[0].second);
		CHECK(channel.opens == 2);
		CHECK(channel.chunks == data.chunk_count());
		net.detach(sid);
	}

	SECTION("a refusal another try would repeat") {
		auto const data = create_data(store, 4500);
		flaky_channel channel;
		channel.failures = 5;
		channel.failure = make_error(protocol::errc::invalid_data_ticket);
		auto sconn = net.create_storage_connection(sid, storage, progress, {}, &store, &channel);
		sconn.attach(output);
		sconn.input().upload_data(data.manifest_digest);
		WAIT_CHECK(output.answered == 1, 2s);
		REQUIRE(output.answers.size() == 1);
		REQUIRE(output.answers[0].second);
		CHECK(output.answers[0].second->code() == make_error_code(protocol::errc::invalid_data_ticket));
		CHECK(channel.opens == 1);
		net.detach(sid);
	}

	SECTION("a download refused by the transfer quota") {
		record_data_store origin{sync::test::create_test_database("comm_upload_test_origin.db"), "comm_upload_test_origin"};
		encryption_key const key{sequence_number{1}, securepath::test::random_octet_vector(crypto::aes_gcm_key_size())};
		auto const plain = securepath::test::random_octet_vector(4500);
		auto writer = origin.create(key, 1000);
		writer.write(plain);
		auto const data = writer.finish();
		auto handle = store.open({key}, data.descriptor, data.header);
		REQUIRE(handle);

		accepting_channel upload_channel;
		quota_holder holder{origin};
		auto sconn = net.create_storage_connection(sid, storage, progress, {}, &store, &upload_channel, &holder);
		sconn.attach(output);
		auto const started = std::chrono::steady_clock::now();
		auto const h = sconn.input().fetch_data(data.descriptor.manifest_digest);

		WAIT_CHECK(output.downloaded == 1, 10s);
		REQUIRE(output.downloads.size() == 1);
		CHECK(output.downloads[0].first == h);
		CHECK(!output.downloads[0].second);
		// the wait the refusal named, not the backoff
		CHECK(std::chrono::steady_clock::now() - started >= 1s);
		CHECK(holder.opens == 2);
		CHECK(handle->state() == record_data_state::in_sync);
		net.detach(sid);
	}

	SECTION("a wait running when the storage connection goes") {
		auto const data = create_data(store, 4500);
		flaky_channel channel;
		channel.failures = 100;
		auto sconn = net.create_storage_connection(sid, storage, progress, {}, &store, &channel);
		sconn.attach(output);
		sconn.input().upload_data(data.manifest_digest);
		WAIT_CHECK(channel.opens == 1, 2s);
		net.detach(sid);
		std::this_thread::sleep_for(1500ms);
		CHECK(channel.opens == 1);
		CHECK(output.answered == 0);
	}
}

}
