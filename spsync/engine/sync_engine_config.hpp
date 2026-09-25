#pragma once

#include <spsync/core/chain_block_id.hpp>
#include <spsync/core/sync_mode.hpp>

#include <securepath/util/octet_vector.hpp>

#include <cstdint>
#include <filesystem>
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
	 * The trusted chain anchor: the block the chain must start with. From the invitation
	 * (plan 5.5, root anchoring): the storage's first record, or after a history cut the
	 * segment record the history starts at (segments plan SEG 5); after a local prune the
	 * segment pruned at. Nothing enters in sync before the anchor is held, and a record
	 * the server shows at the anchor's sequence under another hash is the server showing
	 * another history: refused, reported (engine_output::on_anchor_mismatch) and commits
	 * stop. Retained records below a cut anchor are accepted content authenticated with
	 * an advisory position - the cut kept only the anchor as positional proof. Invalid
	 * for a storage joined without an anchor.
	 */
	chain_block_id trusted_anchor;

	/// the replication mode the storage is expected to have (plan 2.4: replication
	/// requires sign_records, the engine refuses an invalid combination)
	replication_mode replication{replication_mode::none};

	/**
	 * Directory of the storage's record data chunk files (record_data.txt RD6), e.g.
	 * record-storages/<sid>/data next to the storage database. Empty: the storage keeps
	 * no record data - changes with data are refused, the data of others stays deferred.
	 * Used by the owner of the engine (client_sync) to set up the data store.
	 */
	std::filesystem::path data_root;

	/**
	 * Fetch policy for the record data of others (record_data.txt RD6): data up to this
	 * many (encrypted) octets is fetched as soon as its record arrives, bigger data waits
	 * until it is asked for (engine_input::fetch_object_data). 0 = lazy, nothing is
	 * fetched unasked - the mobile default.
	 */
	std::uint64_t auto_fetch_max_size{};

	/// this is id for the repository, it is only used for logging to help trace/debug things if set
	std::string log_id;
};

}

