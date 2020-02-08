#include "chain_sync.hpp"

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

namespace securepath::sync {

chain_sync::chain_sync(database::connection_ptr db, chain_sync_config config)
: config_(std::move(config))
, records_(db)
, last_block_(records_.last_block())
{
}

chain_block chain_sync::set_and_save_block(chain_block block) {
	block.set_server_sequence_and_parent_hash(last_block_.sequence+1, last_block_.hash);
	records_.create(block, record_state::in_sync);
	last_block_ = block.id();
	LOG_TRACE("committed block [block id=(%,%), tag=%] (%)", last_block_.sequence, to_hex(last_block_.hash), to_hex(block.tag()), config_.log_id);
	return block;
}
/*
enum class sync_mode {
	allow_all,
	require_special_seen,
	require_data_add_remove_seen,
	require_all_seen
};

	sequence_number last_data_add_;
	sequence_number last_data_remove_;
	sequence_number last_user_change_or_segment_;

type, last seen seq
*/

//q: check something else? encryption key id?

error chain_sync::can_block_be_committed(chain_block const& block) const {
	error err;
	auto handle = records_.find_tag(block.tag());
	if(!handle) {
		if(config_.mode != sync_mode::allow_all) {
			err = block.deserialise_record<error>([this](auto const& rec){ return check_rules(rec); });
		}
	} else {
		//err = make_error(errc::record_already_committed);
	}
	return err;
}

error chain_sync::check_rules(data_change_record const& rec) const {
	error err;
	if(config_.mode >= sync_mode::require_data_add_remove_seen) {
		for(auto it = rec.begin(); it != rec.end() && !err; ++it) {
			if(it->data.id.is_valid()) {
				//err = make_error(errc::invalid_record);
			} else {
				auto handle = records_.find_last(it->data.id);
				if(!handle && it->data.previous_oid_record_tag.empty()) {
					// add
				} else {
				}
				//previous_oid_record_tag
			}
		}
	}
	return err;
}

error chain_sync::check_rules(user_change_record const& rec) const {
	error err;
	if(config_.mode >= sync_mode::require_data_add_remove_seen) {

	}
	return err;
}

error chain_sync::check_rules(segment_record const& rec) const {
	return error();
}

util::result<chain_block> chain_sync::commit_block(chain_block const& block) {
	util::result<chain_block> res;
	try {
		error err = can_block_be_committed(block);
		if(!err) {
			res = set_and_save_block(block);
		} else {
			LOG_WARN("error while processing new block [err=%, block tag=%] (%)", err, to_hex(block.tag()), config_.log_id);
		}
	} catch(error const& err) {
		LOG_WARN("exception while processing new block [err=%, block tag=%] (%)", err, to_hex(block.tag()), config_.log_id);
		res = err;
	} catch(std::exception const& exp) {
		LOG_WARN("exception while processing new block [exp=%, block tag=%] (%)", exp.what(), to_hex(block.tag()), config_.log_id);
		res = make_error(securepath::errc::exception_occurred);
	}
	return res;
}

}

