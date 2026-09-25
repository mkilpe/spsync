// SPDX-License-Identifier: MIT

#include "transfer_budget.hpp"

#include <algorithm>

namespace securepath::sync {
transfer_budget::transfer_budget(transfer_quota quota)
: quota_(quota)
{
}

std::int64_t transfer_budget::window_of(time_point now) const {
	auto const length = std::max<std::int64_t>(quota_.window.count(), 1);
	return seconds_since_epoch(now) / length;
}

bool transfer_budget::charge(std::uint64_t bytes, time_point now) {
	std::unique_lock lock{mutex_};
	auto const window = window_of(now);
	if(window != window_) {
		window_ = window;
		used_ = 0;
	}
	bool const fits = quota_.bytes_per_window == 0 || (used_ <= quota_.bytes_per_window && bytes <= quota_.bytes_per_window - used_);
	if(fits) {
		used_ += bytes;
	}
	return fits;
}

std::uint64_t transfer_budget::used(time_point now) const {
	std::unique_lock lock{mutex_};
	return window_of(now) == window_ ? used_ : 0;
}

std::uint32_t transfer_budget::retry_after(time_point now) const {
	auto const length = std::max<std::int64_t>(quota_.window.count(), 1);
	return static_cast<std::uint32_t>(length - seconds_since_epoch(now) % length);
}

}
