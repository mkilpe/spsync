// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/types.hpp>

#include <chrono>
#include <mutex>

namespace securepath::sync {

/**
 * Transfer quota of a data server (record_data.txt RD10): how many octets of a storage's
 * data may be served per window. Server-local like the resource quota: a refusal degrades
 * availability only - the client keeps what it fetched and goes on in a later window.
 * 0 octets = no limit.
 */
struct transfer_quota {
	std::uint64_t bytes_per_window{};
	std::chrono::seconds window{3600};
};

/**
 * The served octets of the current window. Windows are fixed and aligned to the epoch,
 * so every restart and every storage agrees on where they are. Kept in memory: a
 * restart opens a fresh window, which errs on the side of serving.
 *
 * Thread safe.
 */
class transfer_budget {
public:
	explicit transfer_budget(transfer_quota quota = {});

	/// count the octets against the window the time is in; false when they do not fit
	/// (nothing is counted then)
	bool charge(std::uint64_t bytes, time_point now);

	/// octets served in the window the time is in
	std::uint64_t used(time_point now) const;

	/// seconds until the window the time is in ends
	std::uint32_t retry_after(time_point now) const;

private:
	std::int64_t window_of(time_point now) const;

private:
	transfer_quota const quota_;
	mutable std::mutex mutex_;
	std::int64_t window_{-1};
	std::uint64_t used_{};
};

}
