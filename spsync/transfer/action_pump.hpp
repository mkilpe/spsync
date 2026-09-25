#pragma once

#include <exception>
#include <functional>
#include <mutex>
#include <vector>
#include <spsync/util/move_only_function.hpp>

namespace securepath::sync {

/**
 * Runs what a transfer state machine wants done - calls into a channel, callbacks to its
 * owner - outside the machine's lock, in rounds that never nest: the machine collects
 * the actions of a round under its own lock, they run without it, and an answer that
 * arrives meanwhile (another thread, or a channel answering inside the call) only flags
 * another round instead of starting one. One thread runs rounds at a time, so the
 * actions run in the order they were collected.
 */
class action_pump {
public:
	using action = move_only_function<void()>;

	/// collect() returns the actions of the next round; it takes the owner's lock itself
	template<typename Collect>
	void run(Collect collect) {
		if(enter()) {
			// a round that throws must not leave the pump taken for good: nothing would
			// ever run again, for any transfer of the machine
			unwind_guard guard{*this};
			bool more = true;
			while(more) {
				std::vector<action> actions = collect();
				for(auto& act : actions) {
					act();
				}
				more = again();
			}
		}
	}

private:
	/// gives the pump up when the runner is left by an exception
	struct unwind_guard {
		explicit unwind_guard(action_pump& p) : pump(p) {}
		unwind_guard(unwind_guard const&) = delete;
		unwind_guard& operator=(unwind_guard const&) = delete;

		~unwind_guard() {
			// more in flight than when the runner started: this scope is being unwound
			// (a count, not a flag - the runner may itself have been called during one)
			if(std::uncaught_exceptions() > exceptions) {
				pump.abandon();
			}
		}

	public:
		action_pump& pump;
		int const exceptions{std::uncaught_exceptions()};
	};

	void abandon() {
		std::unique_lock lock{mutex_};
		running_ = false;
		again_ = false;
	}

	/// true for the caller that becomes the runner; anybody else flags another round
	bool enter() {
		std::unique_lock lock{mutex_};
		bool const runner = !running_;
		running_ = true;
		again_ = again_ || !runner;
		return runner;
	}

	/// another round was asked for meanwhile, else the runner is done
	bool again() {
		std::unique_lock lock{mutex_};
		bool const more = again_;
		again_ = false;
		running_ = more;
		return more;
	}

private:
	std::mutex mutex_;
	bool running_{};
	bool again_{};
};

}
