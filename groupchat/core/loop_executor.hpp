// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/event_system/event_handler.hpp>

#include <functional>
#include <utility>

namespace securepath::groupchat {

/// a function posted to an event handler's loop; the handler runs it in its dispatch
struct run_on_loop {
	typedef void type(std::function<void()>);
};

/**
 * Executor (securepath::executor concept) that runs work on the event loop thread of a
 * handler: the work is posted as a run_on_loop event, so the handler's handle_event must
 * dispatch run_on_loop to loop_executor::run. Lets coroutines resume on the loop
 * (securepath::schedule / resume_on) and non-loop threads hand work to it.
 */
class loop_executor {
public:
	explicit loop_executor(event_system::event_handler& handler)
	: handler_(&handler)
	{}

	void execute(std::function<void()> work) const {
		handler_->emit<run_on_loop>(std::move(work));
	}

	/// the dispatch target of the run_on_loop event
	static void run(std::function<void()> const& work) {
		work();
	}

private:
	event_system::event_handler* handler_;
};

}
