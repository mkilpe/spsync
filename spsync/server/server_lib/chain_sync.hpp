#ifndef SPSYNC_SERVER_CHAIN_SYNC_HEADER
#define SPSYNC_SERVER_CHAIN_SYNC_HEADER

#include <spsync/core/record_storage.hpp>
#include <spsync/util/result.hpp>

#include <securepath/database/connection.hpp>

#include <memory>

namespace securepath::sync {

// status: only the first and last rule implemented for now

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

/**
 * Configuration for server side block chain
 */
struct chain_sync_config {
	/// this is id for the repository, it is only used for logging to help trace/debug things if set
	std::string log_id;
	sync_mode mode{sync_mode::require_all_seen};
};

/**
 * Server side block chain handler
 */
class chain_sync {
public:
	chain_sync(database::connection_ptr, chain_sync_config config = {});

	util::result<chain_block> commit_block(chain_block const&);

private:
	chain_block set_and_save_block(chain_block block);
	error can_block_be_committed(chain_block const& block) const;
	error check_rules(data_change_record const& rec) const;
	error check_rules(user_change_record const& rec) const;
	error check_rules(segment_record const& rec) const;
private:
	chain_sync_config config_;
	record_storage records_;
	chain_block_id last_block_;

	sequence_number last_data_add_;
	sequence_number last_data_remove_;
	sequence_number last_user_change_or_segment_;
};

}

#endif
