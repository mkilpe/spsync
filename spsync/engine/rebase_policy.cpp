// SPDX-License-Identifier: MIT

#include "rebase_policy.hpp"

namespace securepath::sync {

bool needs_rebase(rebase_state const& s) {
	if(s.mode == sync_mode::require_all_seen) {
		return s.last_seen != s.head;
	}

	// weak modes below
	if(s.type == segment_record_tag) {
		// the server requires segments to be committed at the head in any mode above allow_all
		return s.mode >= sync_mode::require_special_seen && s.last_seen != s.head;
	}

	// tag bound (plan 4.3): the reference must be the newest special record, no matter how
	// the sequences relate (a record based on a data record beyond the special is behind too)
	bool const special_behind = s.mode >= sync_mode::require_special_seen
		&& !s.newest_special.empty() && s.special_ref != s.newest_special;

	if(s.type == user_change_record_tag) {
		return special_behind;
	}

	// data change record
	if(special_behind) {
		return true;
	}
	if(s.mode == sync_mode::require_data_add_remove_seen && s.has_adds) {
		return s.last_data_add.is_valid() && s.last_data_add > s.last_seen.sequence;
	}
	return false;
}

}
