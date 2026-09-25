// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/transfer/transfer_retry.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/network/net_error.hpp>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

namespace securepath::sync {

using namespace std::chrono_literals;

// RDS 7: the wait a refusal names survives the way from the wire to whoever retries
TEST_CASE("retry after error", "[unit]") {
	auto const err = protocol::make_retry_error(protocol::errc::data_transfer_quota_exceeded, 42);
	CHECK(err.code() == make_error_code(protocol::errc::data_transfer_quota_exceeded));
	CHECK(protocol::retry_after(err) == 42s);
	CHECK(protocol::retry_after(protocol::make_retry_error(protocol::errc::data_quota_exceeded, 0)) == 0s);

	CHECK(!protocol::retry_after(make_error(protocol::errc::data_transfer_quota_exceeded)));
	CHECK(!protocol::retry_after(make_error(protocol::errc::data_transfer_quota_exceeded, "retry after soon")));
	CHECK(!protocol::retry_after(make_error(protocol::errc::data_transfer_quota_exceeded, "retry after 12 seconds")));
	CHECK(!protocol::retry_after(make_error(securepath::errc::timeout, "retry after 5")));
	CHECK(!protocol::retry_after(error{}));
}

TEST_CASE("retryable transfer errors", "[unit]") {
	// another try may do it
	CHECK(retryable_transfer_error(make_error(securepath::errc::invalid_state, "data connection closed")));
	CHECK(retryable_transfer_error(make_error(securepath::errc::timeout)));
	CHECK(retryable_transfer_error(error(std::make_error_code(std::errc::connection_refused))));
	CHECK(retryable_transfer_error(make_error(protocol::errc::data_ticket_expired)));
	CHECK(retryable_transfer_error(make_error(protocol::errc::data_transfer_quota_exceeded)));
	CHECK(retryable_transfer_error(make_error(protocol::errc::data_quota_exceeded)));
	CHECK(retryable_transfer_error(make_error(protocol::errc::storage_syncing)));

	// another try would say the same
	CHECK(!retryable_transfer_error(make_error(protocol::errc::invalid_data_ticket)));
	CHECK(!retryable_transfer_error(make_error(protocol::errc::invalid_data_manifest)));
	CHECK(!retryable_transfer_error(make_error(protocol::errc::invalid_data_chunk)));
	CHECK(!retryable_transfer_error(make_error(protocol::errc::unknown_data)));
	CHECK(!retryable_transfer_error(make_error(protocol::errc::no_data_servers)));
	CHECK(!retryable_transfer_error(make_error(securepath::errc::not_supported)));
	CHECK(!retryable_transfer_error(make_error(securepath::errc::no_such_data)));
	CHECK(!retryable_transfer_error(make_error(protocol::errc::data_pruned)));
	// (review 2026-09-21) the data server is not the one the grant names
	CHECK(!retryable_transfer_error(make_error(protocol::errc::invalid_client_key)));
	// the owner's news (remote_not_complete), ended by a notification
	CHECK(!retryable_transfer_error(make_error(protocol::errc::data_not_held)));
	CHECK(!retryable_transfer_error(error{}));
}

// (review 2026-09-21) the wait a server asks for is its word, not a failure to back off
// from, and not to be believed beyond reason (a uint32 of seconds is 136 years)
TEST_CASE("transfer retry hint", "[unit]") {
	asio::io_context io;
	auto guard = asio::make_work_guard(io);
	std::jthread runner{[&] { io.run(); }};
	std::atomic<int> fired{0};
	auto const id = securepath::test::random_octet_vector(64);
	{
		transfer_retry_config config{100ms, 5000ms};
		config.max_hint = 150ms;
		transfer_retry retry{io, config, [&](data_id const&) { ++fired; }};
		auto const start = std::chrono::steady_clock::now();
		retry.schedule(id, std::chrono::seconds{4000000000u});
		WAIT_REQUIRE(fired == 1, 3s);
		CHECK(std::chrono::steady_clock::now() - start >= 140ms);
		// the hints did not move the backoff: the next plain retry is the first one
		retry.schedule(id, std::chrono::seconds{0});
		WAIT_REQUIRE(fired == 2, 3s);
		auto const plain = std::chrono::steady_clock::now();
		retry.schedule(id);
		WAIT_REQUIRE(fired == 3, 3s);
		CHECK(std::chrono::steady_clock::now() - plain < 190ms + 300ms);
	}
	guard.reset();
	io.stop();
}

namespace {

/// an io thread for the retry timers and a record of every data that fired, with when
struct retry_fixture {
	retry_fixture()
	: runner{[this] { io.run(); }}
	{
	}

	~retry_fixture() {
		guard.reset();
		io.stop();
	}

	/// what the retry calls: notes the data and the time
	std::function<void(data_id const&)> on_fire() {
		return [this](data_id const& id) {
			std::unique_lock lock{mutex};
			fired.emplace_back(id, std::chrono::steady_clock::now());
		};
	}

	std::size_t count() {
		std::unique_lock lock{mutex};
		return fired.size();
	}

	std::chrono::steady_clock::time_point last_fired() {
		std::unique_lock lock{mutex};
		return fired.back().second;
	}

public:
	asio::io_context io;
	asio::executor_work_guard<asio::io_context::executor_type> guard{asio::make_work_guard(io)};
	std::jthread runner;
	std::mutex mutex;
	std::vector<std::pair<data_id, std::chrono::steady_clock::time_point>> fired;
};

/// the backoff of a data doubles up to the maximum: 100, 200, 250
void check_backoff_doubles(retry_fixture& f, transfer_retry& retry, data_id const& a) {
	auto start = std::chrono::steady_clock::now();
	std::vector<std::chrono::milliseconds> waits;
	for(std::size_t i = 0; i != 3; ++i) {
		retry.schedule(a);
		CHECK(retry.waiting() == 1);
		WAIT_REQUIRE(f.count() == i + 1, 3s);
		waits.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(f.last_fired() - start));
		start = f.last_fired();
		CHECK(retry.waiting() == 0);
	}
	CHECK(waits[0] >= 90ms);
	CHECK(waits[1] >= 190ms);
	CHECK(waits[2] >= 240ms);
	CHECK(waits[2] < 1000ms);
}

/// a forgotten data starts its backoff over, another data has its own, and the wait an
/// error names wins over the backoff
void check_forget_and_hint(retry_fixture& f, transfer_retry& retry, data_id const& a, data_id const& b) {
	// forgotten: the backoff starts over; another data has its own
	retry.forget(a);
	auto start = std::chrono::steady_clock::now();
	retry.schedule(a);
	retry.schedule(b);
	WAIT_REQUIRE(f.count() == 5, 3s);
	CHECK(std::chrono::steady_clock::now() - start < 190ms + 300ms);

	// what the error says wins over the backoff
	start = std::chrono::steady_clock::now();
	retry.schedule(a, 1s);
	WAIT_REQUIRE(f.count() == 6, 5s);
	CHECK(f.last_fired() - start >= 990ms);
}

/// cancelled and forgotten waits never fire
void check_cancelled(retry_fixture& f, transfer_retry& retry, data_id const& a, data_id const& b) {
	retry.schedule(a);
	retry.schedule(b);
	retry.forget(a);
	CHECK(retry.waiting() == 1);
	retry.cancel();
	CHECK(retry.waiting() == 0);
	std::this_thread::sleep_for(400ms);
	CHECK(f.count() == 6);
}

}

TEST_CASE("transfer retry", "[unit]") {
	retry_fixture f;
	auto const a = securepath::test::random_octet_vector(64);
	auto const b = securepath::test::random_octet_vector(64);
	{
		transfer_retry retry{f.io, transfer_retry_config{100ms, 250ms}, f.on_fire()};
		check_backoff_doubles(f, retry, a);
		check_forget_and_hint(f, retry, a, b);
		check_cancelled(f, retry, a, b);

		// a wait running when the owner goes
		retry.schedule(b);
	}
	std::this_thread::sleep_for(300ms);
	CHECK(f.count() == 6);
}

}
