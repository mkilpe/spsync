#pragma once

#include <spsync/core/sync_mode.hpp>

namespace securepath::sync {

/**
 * The configuration for the sync engine
 */
struct sync_engine_config {
	/// sync mode, this has to match the mode set on the server
	sync_mode mode{sync_mode::require_all_seen};

	/// record authentication mode
	sync::auth_mode auth_mode{sync::auth_mode::only_tag};

	/// this is id for the repository, it is only used for logging to help trace/debug things if set
	std::string log_id;
};

}

