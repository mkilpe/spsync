#ifndef SPSYNC_ENGINE_REBASE_POLICY_HEADER
#define SPSYNC_ENGINE_REBASE_POLICY_HEADER

#include <spsync/core/chain_block_id.hpp>
#include <spsync/core/records/record_types.hpp>
#include <spsync/core/sync_mode.hpp>
#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * The state that decides whether a pending record has to be rebuilt on top of the
 * current head before (re)committing. Mirrors the server side rules in chain_sync.
 */
struct rebase_state {
	sync_mode mode{};
	record_type_tag type{};
	/// data change containing at least one add (a change without previous oid record tag)
	bool has_adds{};
	/// the authenticated last seen block of the pending record
	chain_block_id last_seen;
	/// the newest in sync block
	chain_block_id head;
	/// newest in sync user change/segment sequence
	sequence_number last_special;
	/// newest in sync data add sequence
	sequence_number last_data_add;
};

/**
 * Returns whether the pending record would be rejected by the server in this state and so
 * has to be rebased. Per mode:
 *   require_all_seen             rebase on every head move
 *   require_special_seen         rebase when a newer special record exists (segments: head)
 *   require_data_add_remove_seen as above, plus a newer data add for adding records
 *   allow_all                    never (object id conflicts are handled separately)
 */
bool needs_rebase(rebase_state const&);

}

#endif
