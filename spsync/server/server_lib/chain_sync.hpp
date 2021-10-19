#ifndef SPSYNC_SERVER_CHAIN_SYNC_HEADER
#define SPSYNC_SERVER_CHAIN_SYNC_HEADER

#include <spsync/core/sync_mode.hpp>
#include <spsync/core/record_storage.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/util/result.hpp>

#include <securepath/database/connection.hpp>

#include <memory>

namespace securepath::sync {

// t: check and update user access when handling records
// t: check signature

/**
 * Configuration for server side block chain
 */
struct chain_sync_config {
	sync_mode mode{sync_mode::require_all_seen};
	sync::auth_mode	auth_mode{sync::auth_mode::only_tag};
	/// this is id for the repository, it is only used for logging to help trace/debug things if set
	std::string log_id;
	/// maximum records returned for one call
	std::size_t max_returned_records{30};
};

/**
 * Server side block chain handler
 */
class chain_sync {
public:
	chain_sync(database::connection_ptr, chain_sync_config config = {});

	/// returns the latest sequence number
	sequence_number current_sequence_number() const;

	/// get the records [start, end], returns only maximum of config.max_returned_records at once
	std::deque<chain_block> get_records(sequence_number start, sequence_number end) const;

	/// try to commit chain block
	util::result<chain_block> commit_block(chain_block const&);

	record_storage& records() { return records_; }
	record_storage const& records() const { return records_; }

private:
	chain_block set_and_save_block(chain_block block);
	error can_block_be_committed(chain_block const& block) const;
	error check_rules(data_change_record const& rec) const;
	error check_rules(user_change_record const& rec) const;
	error check_rules(segment_record const& rec) const;
	error check_rules_add(data_change_record const& rec, single_change const& change) const;
	error check_rules_existing(data_change_record const& rec, single_change const& change) const;
	error check_rules_special_seen(chain_block_id const& last_seen_block) const;
private:
	chain_sync_config config_;
	record_storage records_;
	chain_block_id last_block_;

	sequence_number last_data_add_remove_;
	sequence_number last_user_change_or_segment_;

	mutable enum class rec_type { none, data_add_remove, special } current_record_{rec_type::none};
};

}

#endif
