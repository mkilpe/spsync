#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/comm/data_channel.hpp>
#include <spsync/comm/net_connection.hpp>
#include <spsync/core/data/record_data_store.hpp>
#include <spsync/core/progress.hpp>

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
	void on_data_downloaded(request_handle, std::optional<error>) override {}
	void on_commit_response(request_handle, commit_response const&) override {}
	void on_record_received(chain_block const&, std::optional<block_envelope> const&) override {}

	void on_data_uploaded(request_handle h, std::optional<error> err) override {
		std::unique_lock lock{mutex};
		answers.emplace_back(h, std::move(err));
		++answered;
	}

	std::atomic<int> answered{0};
	std::mutex mutex;
	std::vector<std::pair<request_handle, std::optional<error>>> answers;
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

}
