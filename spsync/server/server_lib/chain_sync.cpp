#include "chain_sync.hpp"

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <spsync/protocol/error.hpp>

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

//q: check something else? encryption key id?

error chain_sync::can_block_be_committed(chain_block const& block) const {
	error err;
	auto handle = records_.find_tag(block.tag());
	if(!handle) {
		err = block.deserialise_record<error>([this](auto const& rec){ return check_rules(rec); });
	} else {
		err = make_error(protocol::errc::record_already_committed);
	}
	return err;
}

error chain_sync::check_rules(data_change_record const& rec) const {
	error err;
	for(auto it = rec.begin(); it != rec.end() && !err; ++it) {
		LOG_TRACE("GGG: % -- %", it->data.id, to_hex(it->data.previous_oid_record_tag));
		if(!it->data.id.is_valid()) {
			LOG_TRACE("data id is invalid [id=%] (%)", it->data.id, config_.log_id);
			err = make_error(protocol::errc::invalid_record);
		} else {
			auto handle = records_.find_last(it->data.id);
			if(!handle && it->data.previous_oid_record_tag.empty()) {
				LOG_TRACE("AAA % -- %", !!handle, it->data.previous_oid_record_tag.size());
				// add
				if(config_.mode == sync_mode::require_data_add_remove_seen) {

				} else if(config_.mode == sync_mode::require_all_seen) {
					if(rec.last_seen_block() != last_block_) {
						err = make_error(protocol::errc::record_out_of_sync);
					}
				}
			} else if(handle && handle->tag() == it->data.previous_oid_record_tag) {
				LOG_TRACE("BBB");
				if(config_.mode == sync_mode::require_all_seen) {
					if(rec.last_seen_block() != last_block_) {
						err = make_error(protocol::errc::record_out_of_sync);
					}
				}
			} else {
				LOG_TRACE("previous oid is invalid [oid=%] (%)", to_hex(it->data.previous_oid_record_tag), config_.log_id);
				err = make_error(protocol::errc::invalid_record);
			}
		}
	}
	return err;
}

error chain_sync::check_rules(user_change_record const& rec) const {
	error err;
	if(config_.mode >= sync_mode::require_special_seen) {
		if(rec.last_seen_block() != last_block_) {
			err = make_error(protocol::errc::record_out_of_sync);
			LOG_TRACE("out of sync [(%,%) != (%,%) (%)"
				, last_block_.sequence, to_hex(last_block_.hash), rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
		}
	}
	return err;
}

error chain_sync::check_rules(segment_record const& rec) const {
	error err;
	if(config_.mode >= sync_mode::require_special_seen) {
		if(rec.last_seen_block() != last_block_) {
			err = make_error(protocol::errc::record_out_of_sync);
		}
	}
	return err;
}

util::result<chain_block> chain_sync::commit_block(chain_block const& block) {
	util::result<chain_block> res;
	try {
		error err = can_block_be_committed(block);
		if(!err) {
			res = set_and_save_block(block);
		} else {
			res = err;
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

