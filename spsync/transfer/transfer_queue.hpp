#pragma once

#include "action_pump.hpp"
#include "piece_cursor.hpp"
#include "transfer_config.hpp"

#include <spsync/core/data/record_data_store.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <asio/io_context.hpp>
#include <asio/post.hpp>

#include <deque>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace securepath::sync {

/// what every transfer of a data keeps, in either direction
struct transfer_state {
	/// the chunks still to move, piece by piece
	piece_cursor cursor;
	/// the first error; nothing more is moved, the transfer ends when the answers are in
	std::optional<error> failure;
	/// pieces on their way without an answer yet
	std::size_t outstanding{};
	/// encrypted octets moved
	std::uint64_t transferred{};
	/// the holder answered the opening
	bool opened{};
};

/**
 * What the upload and the download queue of a storage share (RD4/RD7): data ids moved a
 * few at a time in the order they were queued, each opened at the holder first and then
 * moved in pieces with a window of them on the way, the pieces of a chunk in order.
 * Answers come from any thread, also before a call returns; the callbacks are made
 * without the lock, one at a time (action_pump); reset() forgets everything and the
 * answers still coming for it fall on the floor (generation). The direction says what
 * opens a transfer, what moves a piece and what a transfer ends with.
 *
 * With an io_context the rounds run on it: enqueue() and the answers only queue one,
 * so neither the thread that queues a data (the engine, with its mutex held) nor the
 * one that delivers an answer (a connection's strand) reads chunks and sends packets.
 * Without one (tests) the caller runs the round itself, at once.
 *
 * Everything but the public functions requires the mutex unless said otherwise.
 */
template<typename Transfer>
class transfer_queue : public std::enable_shared_from_this<transfer_queue<Transfer>> {
public:
	using action = action_pump::action;

	transfer_queue(char const* direction, record_data_store& store, transfer_config config
		, transfer_done_callback done, transfer_progress_callback progress, asio::io_context* io)
	: direction_(direction)
	, store_(store)
	, config_(config)
	, done_(std::move(done))
	, progress_(std::move(progress))
	, io_(io)
	{}

	virtual ~transfer_queue() = default;

	/// the owner goes: like reset(), and no round runs any more (one may be queued)
	void close() {
		std::unique_lock lock{mutex_};
		closed_ = true;
		forget();
	}

	/// queue a data; false when it is already queued or on its way
	bool enqueue(data_id const& id) {
		bool added = false;
		{
			std::unique_lock lock{mutex_};
			added = !active_.contains(id) && std::find(queue_.begin(), queue_.end(), id) == queue_.end();
			if(added) {
				queue_.push_back(id);
			}
		}
		if(added) {
			pump();
		}
		return added;
	}

	void reset() {
		std::unique_lock lock{mutex_};
		forget();
	}

	std::size_t queued() const {
		std::unique_lock lock{mutex_};
		return queue_.size();
	}

	std::size_t in_flight() const {
		std::unique_lock lock{mutex_};
		return active_.size();
	}

protected:
	// -- the direction --

	/// the transfer of a queued data starts: fill it in (its cursor from the store's row)
	/// and give the action that opens it at the holder, or the error when the data is not here
	virtual std::optional<error> start(data_id const&, Transfer&, action& opening) = 0;

	/// the next piece starts a chunk: whatever has to be ready for it, or the error when
	/// it cannot be
	virtual std::optional<error> begin_chunk(data_id const&, Transfer&, std::uint64_t) { return std::nullopt; }

	/// the action that moves one piece
	virtual action piece_action(data_id const&, piece_range const&) = 0;

	/// what the transfer ended with: its failure, unless the direction knows better
	virtual std::optional<error> outcome(Transfer const& t) const { return t.failure; }

	// -- for the direction's answer handlers; any thread, they take the lock --

	/// the holder answered the opening: plan(transfer, info) says what to move; a plan
	/// that throws (the store) fails the transfer
	template<typename Info, typename Plan>
	void opened(std::uint64_t generation, data_id const& id, util::result<Info> const& info, Plan plan) {
		answered(generation, id, [&](Transfer& t) {
			if(info) {
				local(t, [&] { plan(t, info.value()); });
				if(!t.failure) {
					t.opened = true;
					notify_progress(id, t);
				}
			} else {
				t.failure = info.get_error();
			}
		});
	}

	/// a piece was answered: taken(transfer) keeps what came or counts what went
	template<typename Taken>
	void piece_answered(std::uint64_t generation, data_id const& id, std::uint64_t chunk_no, std::optional<error> err, Taken taken) {
		answered(generation, id, [&](Transfer& t) {
			--t.outstanding;
			if(err) {
				LOG_INFO("{} of a record data piece failed [data_id={}, chunk={}]: {}", direction_, to_hex(id), chunk_no, *err);
				if(!t.failure) {
					t.failure = std::move(err);
				}
			} else if(!t.failure) {
				local(t, [&] { taken(t); });
				notify_progress(id, t);
			}
		});
	}

	// -- for the direction, under the lock --

	/// a read of the store; one that fails (the database, the disk) reads nothing
	template<typename Read>
	auto read_store(data_id const& id, Read read) const -> decltype(read()) {
		try {
			return read();
		} catch(std::exception const& ex) {
			LOG_WARN("record data store failed [data_id={}]: {}", to_hex(id), ex.what());
		}
		return {};
	}

	/// the generation the actions being built belong to
	std::uint64_t generation() const { return generation_; }

	record_data_store& store() { return store_; }

	/// the pointer that keeps this alive inside an action
	template<typename Self>
	std::shared_ptr<Self> self_as() {
		return std::static_pointer_cast<Self>(this->shared_from_this());
	}

private:
	using active_iterator = typename std::map<data_id, Transfer>::iterator;

	void forget() {
		++generation_;
		queue_.clear();
		active_.clear();
		notifications_.clear();
	}

	/// do what the state asks for, outside the lock (see action_pump): on the io
	/// context when there is one, else here
	void pump() {
		if(io_) {
			asio::post(*io_, [self = this->shared_from_this()] { self->run_rounds(); });
		} else {
			run_rounds();
		}
	}

	void run_rounds() {
		pump_.run([this] {
			std::unique_lock lock{mutex_};
			return closed_ ? std::vector<action>{} : collect();
		});
	}

	std::vector<action> collect() {
		std::vector<action> actions;
		start_queued(actions);
		for(auto it = active_.begin(); it != active_.end();) {
			auto const following = std::next(it);
			fill_window(it->first, it->second, actions);
			// a transfer that could not start its next chunk ends here: no answer comes for it
			finish_if_done(it);
			it = following;
		}
		for(auto& n : notifications_) {
			actions.push_back(std::move(n));
		}
		notifications_.clear();
		return actions;
	}

	void start_queued(std::vector<action>& actions) {
		while(active_.size() < config_.max_datas && !queue_.empty()) {
			data_id id = std::move(queue_.front());
			queue_.pop_front();
			Transfer transfer;
			action opening;
			auto const refused = start(id, transfer, opening);
			if(refused) {
				LOG_WARN("{} of a record data that is not here [data_id={}]: {}", direction_, to_hex(id), *refused);
				notify_done(id, *refused);
			} else {
				active_.emplace(std::move(id), std::move(transfer));
				actions.push_back(std::move(opening));
			}
		}
	}

	void fill_window(data_id const& id, Transfer& t, std::vector<action>& actions) {
		while(t.opened && !t.failure && t.outstanding < config_.window && !t.cursor.done()) {
			auto const starting = t.cursor.starting_chunk();
			auto const refused = starting ? begin_chunk(id, t, *starting) : std::nullopt;
			if(refused) {
				t.failure = refused;
			} else if(auto const piece = t.cursor.next(config_.piece_size)) {
				++t.outstanding;
				actions.push_back(piece_action(id, *piece));
			}
		}
	}

	/**
	 * Work on the local store inside an answer: when it throws (a full disk, the
	 * database) the transfer fails with that - it must not escape into the link's packet
	 * handler, which would take it for a bad packet and close the link every other
	 * transfer shares, nor skip the bookkeeping that ends the transfer.
	 */
	template<typename Work>
	void local(Transfer& t, Work work) {
		try {
			work();
		} catch(...) {
			auto const err = util::current_exception_error();
			LOG_WARN("record data store failed during a {}: {}", direction_, err);
			if(!t.failure) {
				t.failure = err;
			}
		}
	}

	template<typename Handle>
	void answered(std::uint64_t generation, data_id const& id, Handle handle) {
		{
			std::unique_lock lock{mutex_};
			auto it = active_.find(id);
			if(generation == generation_ && it != active_.end()) {
				handle(it->second);
				finish_if_done(it);
			}
		}
		pump();
	}

	void notify_done(data_id const& id, std::optional<error> err) {
		notifications_.push_back([done = done_, id, err = std::move(err)] {
			if(done) {
				done(id, err);
			}
		});
	}

	void notify_progress(data_id const& id, Transfer const& t) {
		if(progress_) {
			notifications_.push_back([progress = progress_, id, transferred = t.transferred, total = t.cursor.descriptor().enc_size] {
				progress(id, transferred, total);
			});
		}
	}

	/// the transfer ends when nothing is left to move and every answer is in
	void finish_if_done(active_iterator it) {
		auto const& t = it->second;
		if(t.outstanding == 0 && (t.failure || (t.opened && t.cursor.done()))) {
			notify_done(it->first, outcome(t));
			active_.erase(it);
		}
	}

private:
	char const* const direction_;
	record_data_store& store_;
	transfer_config const config_;
	transfer_done_callback const done_;
	transfer_progress_callback const progress_;
	asio::io_context* const io_;

	mutable std::mutex mutex_;
	/// waiting datas in the order they were queued
	std::deque<data_id> queue_;
	std::map<data_id, Transfer> active_;
	/// callbacks owed, made by the next round without the lock
	std::vector<action> notifications_;
	/// answers to calls made before a reset carry an older generation and are ignored
	std::uint64_t generation_{};
	bool closed_{};
	action_pump pump_;
};

}
