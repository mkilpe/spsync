#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/test/test_record_data.hpp>

#include <spsync/transfer/net_data_transfers.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/event_system/event_loop.hpp>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <spsync/util/move_only_function.hpp>

namespace securepath::sync {
namespace {

using namespace std::chrono_literals;

std::string const db_name = "net_data_transfers_test.db";
std::filesystem::path const data_root = "net_data_transfers_test";

/// a data of the given size in the store, upload_pending as the engine leaves it
data_descriptor create_data(record_data_store& store, std::size_t size) {
	return test::store_data(store, size).result.descriptor;
}

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

struct transfer_progress : sync::progress {
	using progress::progress;
	~transfer_progress() { stop_handler(); }

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch(*ev, event_dest<progress_events::on_data_progress>(&transfer_progress::on_data_progress));
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

/// the record connection's side of the transfers: the tickets and the ends, as comm gives them
struct record_side {
	/// answers a ticket request as a record connection that is not there does (review O2)
	ticket_source tickets() {
		return [this](data_descriptor const&, data_right, move_only_function<void(util::result<data_grant>)> cb) {
			++asked;
			cb(util::result<data_grant>{make_error(securepath::errc::invalid_state, "not connected to the record server")});
		};
	}

	std::atomic<int> asked{0};
	test::transfer_log uploads;
	test::transfer_log downloads;
};

/// the transfers wired to their record side, as comm does in its constructor
void attached(net_data_transfers& transfers, record_side& side) {
	transfers.attach(side.tickets(), side.uploads.done(), side.downloads.done());
}

}

// (RDS 3) the transfers behind a storage connection: the uploader over the given channel,
// the end through the callback, progress on the progress handler; the real channel
// with its tickets from the record side when no channel is given
TEST_CASE("net data transfers", "[unit]") {
	event_system::single_thread_event_loop loop;
	test::test_context net_context;
	net_context.add_client(1);
	auto& context = net_context.client_context(0);

	auto db = test::fresh_database(db_name, data_root);
	record_data_store store{db, data_root};
	auto const data = create_data(store, 4500);
	transfer_progress progress{loop};
	record_side side;

	SECTION("an upload over the given channel") {
		accepting_channel channel;
		net_data_transfers transfers{context, store, progress, &channel};
		attached(transfers, side);
		transfers.on_connected();
		transfers.upload(data.manifest_digest);
		WAIT_CHECK(side.uploads.count == 1, 2s);
		REQUIRE(side.uploads.finished.size() == 1);
		CHECK(side.uploads.finished[0].first == data.manifest_digest);
		CHECK(!side.uploads.finished[0].second);
		CHECK(channel.chunks == data.chunk_count());
		WAIT_CHECK(progress.last_transferred == data.enc_size, 2s);
		CHECK(progress.last_total == data.enc_size);
		CHECK(progress.uploads > 0);
		CHECK(side.asked == 0);
	}

	SECTION("the real channel is made when none is given") {
		// (RDS 5) its tickets come from the record side, here one that is not connected:
		// the request is answered at once and nothing is tried again while disconnected
		net_data_transfers transfers{context, store, progress};
		attached(transfers, side);
		transfers.upload(data.manifest_digest);
		WAIT_CHECK(side.uploads.count == 1, 2s);
		REQUIRE(side.uploads.finished.size() == 1);
		REQUIRE(side.uploads.finished[0].second);
		CHECK(side.uploads.finished[0].second->code() == make_error_code(securepath::errc::invalid_state));
		CHECK(side.asked == 1);
	}
}

// (RDS 7) a transfer that ended with an error another try may lift is tried again after
// a wait - the record connection is fine, nobody has to reconnect - and the owner hears of
// it once, when it ended for good
TEST_CASE("net data transfers try again", "[unit]") {
	event_system::single_thread_event_loop loop;
	test::test_context net_context;
	net_context.add_client(1);
	auto& context = net_context.client_context(0);

	auto db = test::fresh_database(db_name, data_root);
	record_data_store store{db, data_root};
	transfer_progress progress{loop};
	record_side side;

	SECTION("an upload whose data connection dropped") {
		auto const data = create_data(store, 4500);
		flaky_channel channel;
		net_data_transfers transfers{context, store, progress, &channel};
		attached(transfers, side);
		transfers.on_connected();
		transfers.upload(data.manifest_digest);

		// nothing is reported while it is tried again...
		std::this_thread::sleep_for(300ms);
		CHECK(side.uploads.count == 0);
		CHECK(channel.opens == 1);
		// ...and once when it is through
		WAIT_CHECK(side.uploads.count == 1, 5s);
		REQUIRE(side.uploads.finished.size() == 1);
		CHECK(!side.uploads.finished[0].second);
		CHECK(channel.opens == 2);
		CHECK(channel.chunks == data.chunk_count());
	}

	SECTION("a refusal another try would repeat") {
		auto const data = create_data(store, 4500);
		flaky_channel channel;
		channel.failures = 5;
		channel.failure = make_error(protocol::errc::invalid_data_ticket);
		net_data_transfers transfers{context, store, progress, &channel};
		attached(transfers, side);
		transfers.on_connected();
		transfers.upload(data.manifest_digest);
		WAIT_CHECK(side.uploads.count == 1, 2s);
		CHECK(side.uploads.ended_with(0, protocol::errc::invalid_data_ticket));
		CHECK(channel.opens == 1);
	}

	SECTION("a download refused by the transfer quota") {
		std::string const origin_name = "net_data_transfers_test_origin";
		record_data_store origin{test::fresh_database(origin_name + ".db", origin_name), origin_name};
		auto const key = test::test_group_key(1);
		auto const data = test::store_data(origin, 4500, 1000, key).result;
		auto handle = store.open({key}, data.descriptor, data.header);
		REQUIRE(handle);

		accepting_channel upload_channel;
		quota_holder holder{origin};
		net_data_transfers transfers{context, store, progress, &upload_channel, &holder};
		attached(transfers, side);
		transfers.on_connected();
		auto const started = std::chrono::steady_clock::now();
		transfers.fetch(data.descriptor.manifest_digest);

		WAIT_CHECK(side.downloads.count == 1, 10s);
		REQUIRE(side.downloads.finished.size() == 1);
		CHECK(side.downloads.finished[0].first == data.descriptor.manifest_digest);
		CHECK(!side.downloads.finished[0].second);
		// the wait the refusal named, not the backoff
		CHECK(std::chrono::steady_clock::now() - started >= 1s);
		CHECK(holder.opens == 2);
		CHECK(handle->state() == record_data_state::in_sync);
	}

	SECTION("a wait running when the record connection goes") {
		auto const data = create_data(store, 4500);
		flaky_channel channel;
		channel.failures = 100;
		net_data_transfers transfers{context, store, progress, &channel};
		attached(transfers, side);
		transfers.on_connected();
		transfers.upload(data.manifest_digest);
		WAIT_CHECK(channel.opens == 1, 2s);
		// the wait is over with the connection, without a word: the owner asks again after
		// the reconnect
		transfers.on_disconnected();
		std::this_thread::sleep_for(1500ms);
		CHECK(channel.opens == 1);
		CHECK(side.uploads.count == 0);
	}
}

}
