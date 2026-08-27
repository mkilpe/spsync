#pragma once

#include <spsync/core/sync_mode.hpp>

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

	/// this is id for the repository, it is only used for logging to help trace/debug things if set
	std::string log_id;
};

}

