// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/comm/comm.hpp>
#include <spsync/comm/net_connection.hpp>
#include <spsync/core/data/data_transfers.hpp>
#include <spsync/core/data/record_data_store.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/protocol/error.hpp>

#include <spsync/test/test_context.hpp>
#include <spsync/test/test_progress.hpp>
#include <spsync/test/test_record_data.hpp>
#include <spsync/test/util.hpp>

#include <filesystem>
#include <mutex>
#include <vector>

namespace securepath::sync::client::test {
namespace {

using namespace std::chrono_literals;

/// the transfers behind the connection, as far as comm can tell: what it was asked and
/// what it was given to answer with
struct fake_transfers : data_transfers {
	void attach(ticket_source t, done_callback upload, done_callback download) override {
		tickets = std::move(t);
		upload_done = std::move(upload);
		download_done = std::move(download);
	}

	void upload(data_id const& id) override {
		uploads.push_back(id);
	}

	void fetch(data_id const& id) override {
		fetches.push_back(id);
	}

	void on_connected() override {
		connected = true;
	}

	void on_disconnected() override {
		connected = false;
		++disconnects;
	}

	ticket_source tickets;
	done_callback upload_done;
	done_callback download_done;
	bool connected{};
	int disconnects{};
	std::vector<data_id> uploads;
	std::vector<data_id> fetches;
};

/// the engine's side of comm, as far as transfers go
struct transfer_output : comm_output {
	using comm_output::comm_output;
	~transfer_output() { stop_handler(); }

	void on_connected() override {}
	void on_disconnected(std::optional<error>) override {}
	void on_sequence_number_response(request_handle, result<sequence_info> const&) override {}
	void on_record_response(request_handle, record_response const&) override {}
	void on_commit_response(request_handle, commit_response const&) override {}
	void on_record_received(chain_block const&, std::optional<block_envelope> const&) override {}

	void on_data_downloaded(request_handle h, std::optional<error> err) override {
		std::unique_lock lock{mutex};
		downloads.emplace_back(h, std::move(err));
		++downloaded;
	}

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

struct null_handler : event_system::event_handler {
	using event_handler::event_handler;
	~null_handler() { stop_handler(); }
	void handle_event(std::unique_ptr<event_system::event_base>) override {}
};

/// the storage connection as after the server's hello, and as after the loss of the
/// session - there is no server here
comm& comm_of(storage_connection& sconn) {
	return dynamic_cast<comm&>(sconn.input());
}

void pretend_connected(storage_connection& sconn) {
	comm_of(sconn).on_connected();
}

void pretend_disconnected(storage_connection& sconn) {
	comm_of(sconn).on_disconnected(error{});
}

}

// (RDS 3, RD12) comm and the transfers behind it: a transfer per data with its request
// handle, the end as the answer event on the output's loop, the connection state and the
// tickets passed on. The transfers themselves are tested with net_data_transfers.
TEST_CASE("comm data transfers", "[unit]") {
	event_system::single_thread_event_loop loop;
	sync::test::test_context net_context;
	net_context.add_client(1);

	std::filesystem::remove_all("comm_transfers_test");
	auto db = sync::test::create_test_database("comm_transfers_test.db");
	record_storage storage{db};
	record_data_store store{db, "comm_transfers_test"};
	auto const data = sync::test::store_data(store, 4500).result.descriptor;
	auto const id = data.manifest_digest;

	null_handler handler{loop};
	sync::test::test_progress progress;
	transfer_output output{loop};
	network_connection net{net_context.client_context(0), handler};
	auto const sid = octet_vector(16, 1);

	auto owned = std::make_unique<fake_transfers>();
	auto& transfers = *owned;
	auto sconn = net.create_storage_connection(sid, storage, progress, {}, &store, std::move(owned));
	sconn.attach(output);
	CHECK(sconn.input().data() == &store);
	REQUIRE(transfers.upload_done);
	REQUIRE(transfers.download_done);
	REQUIRE(transfers.tickets);

	SECTION("an upload: one transfer per data, answered with its handle") {
		auto const h = sconn.input().upload_data(id);
		CHECK(transfers.uploads == std::vector<data_id>{id});
		// a data on its way is not asked for again
		CHECK(sconn.input().upload_data(id) == h);
		CHECK(transfers.uploads.size() == 1);

		transfers.upload_done(id, std::nullopt);
		WAIT_CHECK(output.answered == 1, 2s);
		REQUIRE(output.answers.size() == 1);
		CHECK(output.answers[0].first == h);
		CHECK(!output.answers[0].second);
		// ended: the next ask is a new transfer
		CHECK(sconn.input().upload_data(id) != h);
		CHECK(transfers.uploads.size() == 2);
	}

	SECTION("a download, with the error it ended with") {
		auto const h = sconn.input().fetch_data(id);
		CHECK(transfers.fetches == std::vector<data_id>{id});
		CHECK(sconn.input().fetch_data(id) == h);
		transfers.download_done(id, make_error(protocol::errc::data_not_held));
		WAIT_CHECK(output.downloaded == 1, 2s);
		REQUIRE(output.downloads.size() == 1);
		CHECK(output.downloads[0].first == h);
		CHECK(sync::test::is_error(output.downloads[0].second, protocol::errc::data_not_held));
	}

	SECTION("the connection state reaches the transfers") {
		CHECK(!transfers.connected);
		pretend_connected(sconn);
		CHECK(transfers.connected);
		auto const h = sconn.input().upload_data(id);
		pretend_disconnected(sconn);
		CHECK(!transfers.connected);
		CHECK(transfers.disconnects == 1);
		// the transfer went with the connection: its end is nobody's, the next ask is new
		transfers.upload_done(id, std::nullopt);
		auto const again = sconn.input().upload_data(id);
		CHECK(again != h);
		CHECK(transfers.uploads.size() == 2);
		transfers.upload_done(id, std::nullopt);
		WAIT_CHECK(output.answered == 1, 2s);
		REQUIRE(output.answers.size() == 1);
		CHECK(output.answers[0].first == again);
	}

	SECTION("a ticket asked while not connected is answered at once") {
		// (RDS 5, review O2) a request would go into a connection that is not there
		std::optional<util::result<data_grant>> answer;
		transfers.tickets(data, data_right::upload, [&](util::result<data_grant> r) { answer = std::move(r); });
		REQUIRE(answer);
		CHECK(!*answer);
		CHECK(answer->get_error().code() == make_error_code(securepath::errc::invalid_state));
	}

	net.detach(sid);
}

// a storage without record data has no transfers: the asks are answered not_supported
TEST_CASE("comm without record data", "[unit]") {
	event_system::single_thread_event_loop loop;
	sync::test::test_context net_context;
	net_context.add_client(1);

	auto db = sync::test::create_test_database("comm_transfers_test.db");
	record_storage storage{db};
	null_handler handler{loop};
	sync::test::test_progress progress;
	transfer_output output{loop};
	network_connection net{net_context.client_context(0), handler};
	auto const sid = octet_vector(16, 3);

	auto sconn = net.create_storage_connection(sid, storage, progress);
	sconn.attach(output);
	CHECK(sconn.input().data() == nullptr);
	auto const id = octet_vector(64, 9);
	sconn.input().upload_data(id);
	sconn.input().fetch_data(id);
	WAIT_CHECK((output.answered == 1 && output.downloaded == 1), 2s);
	REQUIRE(output.answers.size() == 1);
	REQUIRE(output.downloads.size() == 1);
	REQUIRE(output.answers[0].second);
	CHECK(output.answers[0].second->code() == make_error_code(securepath::errc::not_supported));
	REQUIRE(output.downloads[0].second);
	CHECK(output.downloads[0].second->code() == make_error_code(securepath::errc::not_supported));
	net.detach(sid);
}

}
