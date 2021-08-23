#pragma once

namespace securepath::sync {

/**
 * modes for synchronisation (server rules):
 *	- allow all at any time
 *	- require user change seen and segment has seen everything before it
 *	- require all data change added seen when adding
 *	- require all up-to-date always
 */
enum class sync_mode {
	allow_all,
	require_special_seen,
	require_data_add_remove_seen,
	require_all_seen
};

}
