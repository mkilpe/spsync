#pragma once

#include <spsync/core/sync_mode.hpp>

#include <securepath/util/octet_vector.hpp>

#include <string>

namespace securepath::sync {

/**
 * What the engine does when an object changed underneath a pending record
 * (the object's newest record no longer matches the pending record's previous tag):
 *   rebase_on_top  rewrite the pending change on top of the newest record (last writer
 *                  wins) and notify through engine_output::on_object_conflict
 *   ask            cancel the pending record (state becomes invalid), notify through
 *                  on_object_conflict once and let the higher layer decide; it can
 *                  re-issue the change through the engine_input interface
 */
enum class conflict_policy {
	rebase_on_top = 0,
	ask
};

/// How verify_history checks the stored chain (segments plan SEG 4/S4)
enum class history_verification {
	/// walk every record: hash chain and per-record authenticity
	full = 0,
	/// verify from the newest segment: the records past its stated end fully, the older
	/// history through the authenticated segment backbone
	fast
};

/**
 * The configuration for the sync engine
 */
struct sync_engine_config {
	/// sync mode, this has to match the mode set on the server
	sync_mode mode{sync_mode::require_all_seen};

	/// record authentication mode
	sync::auth_mode auth_mode{sync::auth_mode::only_tag};

	/// what to do when an object changed underneath a pending record
	conflict_policy conflicts{conflict_policy::rebase_on_top};

	/// how verify_history checks the stored chain (segments plan SEG 4)
	history_verification verification{history_verification::fast};

	/**
	 * Block hash of the trusted chain anchor (segments plan SEG 5): the segment record
	 * accepted as the chain start when the history before it was cut on the server. The
	 * hash comes with the invite. Retained records below the anchor are accepted content
	 * authenticated with an advisory position - the cut kept only the anchor as
	 * positional proof. Empty for storages with full history.
	 */
	octet_vector trusted_anchor;

	/// the replication mode the storage is expected to have (plan 2.4: replication
	/// requires sign_records, the engine refuses an invalid combination)
	replication_mode replication{replication_mode::none};

	/// this is id for the repository, it is only used for logging to help trace/debug things if set
	std::string log_id;
};

}

