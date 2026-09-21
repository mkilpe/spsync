#include "transfer_retry.hpp"

#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <asio/steady_timer.hpp>

#include <algorithm>
#include <map>
#include <mutex>

namespace securepath::sync {

bool retryable_transfer_error(error const& err) {
	using protocol::errc;
	auto const is = [&](auto code) { return err.code() == make_error_code(code); };
	bool const pointless = is(errc::invalid_data_ticket) || is(errc::invalid_data_manifest) || is(errc::invalid_data_chunk)
		|| is(errc::unknown_data) || is(errc::no_data_servers) || is(errc::no_such_storage) || is(errc::no_such_upload)
		|| is(securepath::errc::not_supported) || is(securepath::errc::no_such_data);
	bool const owners_news = is(errc::data_not_held);
	return static_cast<bool>(err) && !pointless && !owners_news;
}

class transfer_retry::impl : public std::enable_shared_from_this<impl> {
public:
	impl(asio::io_context& io, transfer_retry_config config, std::function<void(data_id const&)> retry)
	: io_(io)
	, config_(config)
	, retry_(std::move(retry))
	{}

	void schedule(data_id const& id, std::optional<std::chrono::seconds> hint) {
		std::unique_lock lock{mutex_};
		auto& w = waits_.try_emplace(id, io_).first->second;
		auto const delay = hint ? std::chrono::milliseconds{*hint} : w.backoff.value_or(config_.first);
		w.backoff = std::min(w.backoff.value_or(config_.first) * 2, config_.max);
		w.pending = true;
		LOG_INFO("record data transfer tried again in {} ms [data_id={}]", delay.count(), to_hex(id));
		w.timer.expires_after(delay);
		w.timer.async_wait([weak = weak_from_this(), id, generation = generation_](std::error_code const& ec) {
			auto self = weak.lock();
			if(self && !ec) {
				self->fire(id, generation);
			}
		});
	}

	void forget(data_id const& id) {
		std::unique_lock lock{mutex_};
		auto it = waits_.find(id);
		if(it != waits_.end()) {
			it->second.timer.cancel();
			waits_.erase(it);
		}
	}

	void cancel() {
		std::unique_lock lock{mutex_};
		++generation_;
		for(auto& [id, w] : waits_) {
			w.timer.cancel();
		}
		waits_.clear();
	}

	std::size_t waiting() const {
		std::unique_lock lock{mutex_};
		return static_cast<std::size_t>(std::ranges::count_if(waits_, [](auto const& w) { return w.second.pending; }));
	}

private:
	void fire(data_id const& id, std::uint64_t generation) {
		bool due = false;
		{
			std::unique_lock lock{mutex_};
			auto it = waits_.find(id);
			due = generation == generation_ && it != waits_.end() && it->second.pending;
			if(due) {
				// the backoff stays for the next failure of the data
				it->second.pending = false;
			}
		}
		if(due) {
			// under its own lock so that shutdown() can wait the call out
			std::unique_lock calling{call_mutex_};
			if(!stopped_) {
				retry_(id);
			}
		}
	}

public:
	/// after this no retry function runs or will run: the owner may go
	void shutdown() {
		cancel();
		std::unique_lock calling{call_mutex_};
		stopped_ = true;
	}

private:

	struct wait {
		explicit wait(asio::io_context& io) : timer(io) {}

		asio::steady_timer timer;
		/// the wait of the next try; unset before the first one
		std::optional<std::chrono::milliseconds> backoff;
		bool pending{};
	};

private:
	asio::io_context& io_;
	transfer_retry_config const config_;
	std::function<void(data_id const&)> const retry_;

	mutable std::mutex mutex_;
	std::map<data_id, wait> waits_;
	/// waits from before a cancel say nothing any more
	std::uint64_t generation_{};

	std::mutex call_mutex_;
	bool stopped_{};
};

transfer_retry::transfer_retry(asio::io_context& io, transfer_retry_config config, std::function<void(data_id const&)> retry)
: impl_(std::make_shared<impl>(io, config, std::move(retry)))
{
}

transfer_retry::~transfer_retry() {
	impl_->shutdown();
}

void transfer_retry::schedule(data_id const& id, std::optional<std::chrono::seconds> hint) {
	impl_->schedule(id, hint);
}

void transfer_retry::forget(data_id const& id) {
	impl_->forget(id);
}

void transfer_retry::cancel() {
	impl_->cancel();
}

std::size_t transfer_retry::waiting() const {
	return impl_->waiting();
}

}
