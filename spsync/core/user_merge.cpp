// SPDX-License-Identifier: MIT

#include "user_merge.hpp"

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::sync {
namespace {

/// true when ancestor is in the causal past of the entry (walking the special tree)
bool saw(record_tag const& ancestor, record_tag const& from_parent,
	std::map<record_tag, record_tag> const& parent_special) {
	bool found = false;
	auto step = from_parent;
	// the walk is bounded by the tree size; a malformed cycle ends at the map lookup
	std::size_t guard = parent_special.size() + 1;
	while(!found && !step.empty() && guard != 0) {
		--guard;
		found = step == ancestor;
		if(!found) {
			auto it = parent_special.find(step);
			step = it != parent_special.end() ? it->second : record_tag{};
		}
	}
	return found;
}

/// the fold state of one member: the winning update entry
struct member_state {
	util::user_access access;
	record_tag tag;
	record_tag parent_special;
};

/// one recorded removal of a user
struct removal {
	record_tag tag;
	record_tag parent_special;
};

struct fold_state {
	std::map<crypto::public_key_id, member_state> members;
	std::map<crypto::public_key_id, std::vector<removal>> removals;
};

void apply_removal(fold_state& state, crypto::public_key_id const& kid, user_change_entry const& entry,
	std::map<record_tag, record_tag> const& parent_special) {
	auto member = state.members.find(kid);
	// the removal stands unless the current member's update saw it (re-invitation);
	// a concurrent update loses to the removal, fail closed (D9)
	if(member != state.members.end() && !saw(entry.tag, member->second.parent_special, parent_special)) {
		state.members.erase(member);
	}
	state.removals[kid].push_back(removal{entry.tag, entry.parent_special});
}

void apply_update(fold_state& state, crypto::public_key_id const& kid, util::user_access const& access,
	user_change_entry const& entry, std::map<record_tag, record_tag> const& parent_special) {
	// every removal not in this update's causal past defeats it
	bool defeated = false;
	auto removals = state.removals.find(kid);
	if(removals != state.removals.end()) {
		for(auto const& r : removals->second) {
			if(!defeated && !saw(r.tag, entry.parent_special, parent_special)) {
				defeated = true;
			}
		}
	}
	if(!defeated) {
		auto member = state.members.find(kid);
		bool winner = member == state.members.end();
		if(!winner) {
			if(saw(member->second.tag, entry.parent_special, parent_special)) {
				// this update saw the current one: causally newer
				winner = true;
			} else if(!saw(entry.tag, member->second.parent_special, parent_special)) {
				// concurrent updates: the smallest tag wins, deterministically
				winner = entry.tag < member->second.tag;
			}
		}
		if(winner) {
			state.members[kid] = member_state{access, entry.tag, entry.parent_special};
		}
	}
}

}

std::vector<util::user_access> merge_user_changes(std::vector<user_change_entry> const& entries,
	std::map<record_tag, record_tag> const& parent_special) {
	fold_state state;
	for(auto const& entry : entries) {
		if(entry.change.mode() == users_change_mode::full) {
			// legacy full state: everything before it is subsumed
			state = {};
		}
		for(auto const& ua : entry.change.access()) {
			auto const kid = ua.user.public_key_id();
			if(ua.access == util::access_type::no_access) {
				apply_removal(state, kid, entry, parent_special);
			} else {
				apply_update(state, kid, ua, entry, parent_special);
			}
		}
	}

	std::vector<util::user_access> ret;
	for(auto const& [kid, member] : state.members) {
		ret.push_back(member.access);
	}
	return ret;
}

}
