#pragma once

#include <chrono>
#include <map>
#include <optional>
#include <vector>

namespace securepath::sync {

/**
 * The calls of a connection that wait for their answer, by the id the answer names:
 * taken one by one as the answers come, all at once when the connection goes, and by age
 * when an answer is overdue. Not locked: the owner's mutex covers it.
 */
template<typename Key, typename Callback>
class pending_calls {
public:
	using clock = std::chrono::steady_clock;

	void add(Key key, Callback callback) {
		calls_.emplace(std::move(key), entry{std::move(callback), clock::now()});
	}

	std::optional<Callback> take(Key const& key) {
		std::optional<Callback> ret;
		auto it = calls_.find(key);
		if(it != calls_.end()) {
			ret = std::move(it->second.callback);
			calls_.erase(it);
		}
		return ret;
	}

	std::vector<Callback> take_all() {
		std::vector<Callback> ret;
		for(auto& [key, e] : calls_) {
			ret.push_back(std::move(e.callback));
		}
		calls_.clear();
		return ret;
	}

	/// the calls that have waited for the given time or longer
	std::vector<Callback> take_older_than(clock::duration age) {
		std::vector<Callback> ret;
		auto const limit = clock::now() - age;
		for(auto it = calls_.begin(); it != calls_.end();) {
			bool const overdue = it->second.since <= limit;
			if(overdue) {
				ret.push_back(std::move(it->second.callback));
			}
			it = overdue ? calls_.erase(it) : std::next(it);
		}
		return ret;
	}

	bool empty() const { return calls_.empty(); }
	std::size_t size() const { return calls_.size(); }

private:
	struct entry {
		Callback callback;
		clock::time_point since;
	};

	std::map<Key, entry> calls_;
};

}
