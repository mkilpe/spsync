// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>

#include <spsync/transfer/action_pump.hpp>

#include <stdexcept>

namespace securepath::sync {

// the rounds of a transfer machine: collected under its lock, run without it, never nested
TEST_CASE("action pump", "[unit]") {
	action_pump pump;
	std::vector<int> ran;
	int rounds = 0;

	SECTION("a call inside a round flags another round instead of starting one") {
		int depth = 0;
		int deepest = 0;
		std::function<std::vector<action_pump::action>()> collect = [&] {
			++rounds;
			std::vector<action_pump::action> actions;
			if(rounds <= 2) {
				actions.push_back([&] {
					deepest = std::max(deepest, ++depth);
					ran.push_back(rounds);
					// an answer that arrives inside the call
					pump.run(collect);
					--depth;
				});
			}
			return actions;
		};
		pump.run(collect);
		CHECK(ran == std::vector<int>{1, 2});
		CHECK(deepest == 1);
		// the round after the last action found nothing to do
		CHECK(rounds == 3);
	}

	SECTION("a run during the unwinding of something else is a run like any other") {
		// the guard compares counts of exceptions in flight: one that was there before
		// the runner started is not the runner's
		struct runs_on_exit {
			~runs_on_exit() {
				pump.run([this] {
					std::vector<action_pump::action> actions;
					if(!done) {
						actions.push_back([this] { ran.push_back(1); });
					}
					done = true;
					return actions;
				});
			}

		public:
			action_pump& pump;
			std::vector<int>& ran;
			bool done{};
		};
		try {
			runs_on_exit on_exit{pump, ran};
			throw std::runtime_error("something else");
		} catch(std::runtime_error const&) {
		}
		CHECK(ran == std::vector<int>{1});
		// and the pump is free
		pump.run([&] {
			std::vector<action_pump::action> actions;
			if(rounds++ == 0) {
				actions.push_back([&] { ran.push_back(2); });
			}
			return actions;
		});
		CHECK(ran == std::vector<int>{1, 2});
	}

	SECTION("a round that throws gives the pump up") {
		// (review 2026-09-21) it stayed taken: no transfer of the machine ever ran again
		CHECK_THROWS(pump.run([&] {
			std::vector<action_pump::action> actions;
			actions.push_back([] { throw std::runtime_error("the store failed"); });
			return actions;
		}));
		CHECK_THROWS(pump.run([]() -> std::vector<action_pump::action> { throw std::runtime_error("collect failed"); }));

		bool first = true;
		pump.run([&] {
			std::vector<action_pump::action> actions;
			if(first) {
				actions.push_back([&] { ran.push_back(7); });
			}
			first = false;
			return actions;
		});
		CHECK(ran == std::vector<int>{7});
	}
}

}
