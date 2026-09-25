// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/types.hpp>
#include <spsync/core/users.hpp>

#include <map>
#include <vector>

namespace securepath::sync {

/// one user change record as input to the merge fold (plan 4.6/D9)
struct user_change_entry {
	/// the decrypted user change (delta, or full for legacy non-replicated storages)
	users change;
	/// tag of the carrying record
	record_tag tag;
	/// the record's authenticated last_seen_special_tag: its causal parent (plan 4.3)
	record_tag parent_special;
};

/**
 * The D9 semantic merge of user changes (plan 4.6). Entries come in the local storage
 * order; parent_special maps every special record's tag to its last_seen_special_tag,
 * which forms the causal tree the concurrency decisions are made on. The result is
 * deterministic on the SET of entries - the local order never changes the outcome, so
 * every replica derives the same membership:
 *
 *   - a removal defeats every addition of the same user that did not see it (a
 *     concurrent add loses, fail closed), while an addition that has the removal in
 *     its causal past wins (re-invitation works)
 *   - among concurrent effective updates of one user the smallest record tag wins;
 *     the winner's access applies as signed - accesses are never unioned, so a merge
 *     cannot escalate anyone (D9)
 *   - a full mode change resets the fold (legacy single-server storages only; delta
 *     is mandatory on replicated storages)
 */
std::vector<util::user_access> merge_user_changes(std::vector<user_change_entry> const& entries,
	std::map<record_tag, record_tag> const& parent_special);

}
