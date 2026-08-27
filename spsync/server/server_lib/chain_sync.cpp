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
, last_data_add_remove_(records_.last_data_add_sequence())
, last_user_change_or_segment_(records_.last_special_sequence())
{
}

sequence_number chain_sync::current_sequence_number() const {
	return last_block_.sequence;
}

std::deque<chain_block> chain_sync::get_records(sequence_number start, sequence_number end) const {
	std::deque<chain_block> ret;
	record_handle h;
	if(!start.is_valid()) {
		start = sequence_number{1};
	}
	if(!end.is_valid()) {
		end = current_sequence_number();
	}
	for(; start <= end && (h = records_.find(start)) && ret.size() < config_.max_returned_records; ++start) {
		ret.push_back(h->record());
	}
	return ret;
}

chain_block chain_sync::set_and_save_block(chain_block block, rec_type type) {
	block.set_sequence_and_parent_hash(last_block_.sequence+1, last_block_.hash);
	records_.create(block, record_state::in_sync);
	last_block_ = block.id();
	if(type == rec_type::data_add_remove) {
		last_data_add_remove_ = block.sequence();
	} else if(type == rec_type::special) {
		last_user_change_or_segment_ = block.sequence();
	}
	LOG_TRACE("committed block [block id=({},{}), tag={}, type={}] (rsid={})", last_block_.sequence, to_hex(last_block_.hash), to_hex(block.tag()), int(type), config_.log_id);
	return block;
}

chain_sync::rule_result chain_sync::evaluate(chain_block const& block) const {
	rule_result r;
	auto handle = records_.find_tag(block.tag());
	if(!handle) {
		r = block.deserialise_record<rule_result>([this](auto const& rec){ return check_rules(rec); });
	} else {
		r.err = make_error(protocol::errc::record_already_committed);
	}
	return r;
}

error chain_sync::check_rules_add(data_change_record const& rec) const {
	error err;
	if(config_.mode == sync_mode::require_all_seen) {
		if(rec.last_seen_block() != last_block_) {
			LOG_TRACE("out of sync [({},{}) != ({},{}) (rsid={})"
				, last_block_.sequence, to_hex(last_block_.hash), rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
			err = make_error(protocol::errc::record_out_of_sync);
		}
	} else {
		err = check_rules_special_seen(rec.last_seen_block());
		if(!err && config_.mode == sync_mode::require_data_add_remove_seen) {
			if(last_data_add_remove_.is_valid() && last_data_add_remove_ > rec.last_seen_block().sequence) {
				err = make_error(protocol::errc::record_out_of_sync);
				LOG_TRACE("out of sync (not seen all data adds/removes) [{} > {} ({})] (rsid={})"
					, last_data_add_remove_, rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
			}
		}
	}
	return err;
}

error chain_sync::check_rules_existing(data_change_record const& rec) const {
	error err;
	if(config_.mode == sync_mode::require_all_seen) {
		if(rec.last_seen_block() != last_block_) {
			LOG_TRACE("out of sync [({},{}) != ({},{}) (rsid={})"
				, last_block_.sequence, to_hex(last_block_.hash), rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
			err = make_error(protocol::errc::record_out_of_sync);
		}
	} else {
		err = check_rules_special_seen(rec.last_seen_block());
	}
	return err;
}

chain_sync::rule_result chain_sync::check_rules(data_change_record const& rec) const {
	rule_result r;
	for(auto it = rec.begin(); it != rec.end() && !r.err; ++it) {
		if(!it->data.id.is_valid()) {
			LOG_TRACE("data id is invalid [id={}] (rsid={})", it->data.id, config_.log_id);
			r.err = make_error(protocol::errc::invalid_record);
		} else {
			auto handle = records_.find_last(it->data.id);
			if(!handle && it->data.previous_oid_record_tag.empty()) {
				r.type = rec_type::data_add_remove;
				r.err = check_rules_add(rec);
			} else if(handle && handle->tag() == it->data.previous_oid_record_tag) {
				r.err = check_rules_existing(rec);
			} else {
				LOG_TRACE("previous oid record tag is invalid [oid={}] (rsid={})", to_hex(it->data.previous_oid_record_tag), config_.log_id);
				r.err = make_error(protocol::errc::record_out_of_sync);
			}
		}
	}
	return r;
}

error chain_sync::check_rules_special_seen(chain_block_id const& last_seen_block) const {
	error err;
	if(config_.mode >= sync_mode::require_special_seen) {
		if(last_user_change_or_segment_.is_valid() && last_user_change_or_segment_ > last_seen_block.sequence) {
			err = make_error(protocol::errc::record_out_of_sync);
			LOG_TRACE("out of sync (not seen all special changes) [{} > {} ({})] (rsid={})"
				, last_user_change_or_segment_, last_seen_block.sequence, to_hex(last_seen_block.hash), config_.log_id);
		}
	}
	return err;
}

chain_sync::rule_result chain_sync::check_rules(user_change_record const& rec) const {
	rule_result r;
	r.type = rec_type::special;
	if(config_.mode == sync_mode::require_all_seen) {
		if(rec.last_seen_block() != last_block_) {
			r.err = make_error(protocol::errc::record_out_of_sync);
			LOG_TRACE("out of sync [({},{}) != ({},{}) (rsid={})"
				, last_block_.sequence, to_hex(last_block_.hash), rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
		}
	} else {
		r.err = check_rules_special_seen(rec.last_seen_block());
	}
	return r;
}

chain_sync::rule_result chain_sync::check_rules(segment_record const& rec) const {
	rule_result r;
	r.type = rec_type::special;
	if(config_.mode >= sync_mode::require_special_seen) {
		if(rec.last_seen_block() != last_block_) {
			r.err = make_error(protocol::errc::record_out_of_sync);
			LOG_TRACE("out of sync [({},{}) != ({},{}) (rsid={})"
				, last_block_.sequence, to_hex(last_block_.hash), rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
		}
	}
	return r;
}

error chain_sync::validate(chain_block const& block) const {
	try {
		return evaluate(block).err;
	} catch(error const& err) {
		return err;
	} catch(std::exception const& exp) {
		LOG_WARN("exception while validating block [exp={}] (rsid={})", exp.what(), config_.log_id);
		return make_error(securepath::errc::exception_occurred);
	}
}

chain_block chain_sync::apply(chain_block const& block) {
	// classification uses the same rule evaluation; any validation error is the caller's
	// responsibility to have handled beforehand
	auto r = evaluate(block);
	return set_and_save_block(block, r.type);
}

util::result<chain_block> chain_sync::commit_block(chain_block const& block) {
	LOG_TRACE("commit_block (rsid={})", config_.log_id);
	util::result<chain_block> res;
	try {
		auto r = evaluate(block);
		if(!r.err) {
			res = set_and_save_block(block, r.type);
		} else {
			res = r.err;
			LOG_WARN("error while processing new block [err={}, block tag={}] (rsid={})", r.err, to_hex(block.tag()), config_.log_id);
		}
	} catch(error const& err) {
		LOG_WARN("exception while processing new block [err={}, block tag={}] (rsid={})", err, to_hex(block.tag()), config_.log_id);
		res = err;
	} catch(std::exception const& exp) {
		LOG_WARN("exception while processing new block [exp={}, block tag={}] (rsid={})", exp.what(), to_hex(block.tag()), config_.log_id);
		res = make_error(securepath::errc::exception_occurred);
	}
	return res;
}

}
