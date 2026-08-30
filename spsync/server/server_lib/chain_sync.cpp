#include "chain_sync.hpp"

#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <spsync/protocol/error.hpp>

#include <securepath/crypto/error.hpp>
#include <securepath/crypto/public_key_access.hpp>

namespace securepath::sync {

chain_sync::chain_sync(database::connection_ptr db, chain_sync_config config, crypto::public_key_access* keys)
: config_(std::move(config))
, keys_(keys)
, log_(db)
, last_data_add_remove_(log_.records().last_data_add_sequence())
, last_user_change_or_segment_(log_.records().last_special_sequence())
{
}

sequence_number chain_sync::current_sequence_number() const {
	return log_.head().sequence;
}

std::deque<chain_block> chain_sync::get_records(sequence_number start, sequence_number end) const {
	std::deque<chain_block> ret;
	for(auto const& env : log_.get(start, end, config_.max_returned_records)) {
		ret.push_back(env.block());
	}
	return ret;
}

std::vector<chain_block> chain_sync::truncate_from(sequence_number first_removed) {
	auto removed = log_.truncate_from(first_removed);
	last_data_add_remove_ = log_.records().last_data_add_sequence();
	last_user_change_or_segment_ = log_.records().last_special_sequence();
	return removed;
}

chain_block chain_sync::set_and_save_block(chain_block block, rec_type type) {
	auto const head = log_.head();
	block.set_sequence_and_parent_hash(head.sequence+1, head.hash);
	// the local commit path signs the assignment after the sequence is set (storage layer),
	// so the block is appended in an unsigned envelope here
	log_.append(block_envelope{block, {}});
	if(type == rec_type::data_add_remove) {
		last_data_add_remove_ = block.sequence();
	} else if(type == rec_type::special) {
		last_user_change_or_segment_ = block.sequence();
	}
	LOG_TRACE("committed block [block id=({},{}), tag={}, type={}] (rsid={})", block.sequence(), to_hex(block.hash()), to_hex(block.tag()), int(type), config_.log_id);
	return block;
}

error chain_sync::verify_signature(chain_block const& block, std::optional<crypto::public_key_id>& signer) const {
	auto auth = block.auth();
	if(!auth.has_signature()) {
		LOG_WARN("record is not signed in sign_records mode [tag={}] (rsid={})", to_hex(block.tag()), config_.log_id);
		return make_error(protocol::errc::invalid_record, "record is not signed");
	}
	if(keys_) {
		auto err = auth.verify(*keys_, block.record_bytes());
		if(err) {
			if(err.code() == make_error_code(crypto::errc::no_such_key)) {
				LOG_INFO("record signer is unknown [tag={}] (rsid={})", to_hex(block.tag()), config_.log_id);
				return make_error(protocol::errc::unknown_signer);
			}
			LOG_WARN("record signature is not authentic [tag={}] (rsid={})", to_hex(block.tag()), config_.log_id);
			return make_error(protocol::errc::invalid_record, "record signature is not authentic");
		}
	}
	signer = auth.signature_issuer();
	// t: phase 7 checks the signer's access rights for this storage here
	return {};
}

chain_sync::rule_result chain_sync::evaluate(chain_block const& block) const {
	rule_result r;
	auto handle = log_.find_by_tag(block.tag());
	if(!handle) {
		if(config_.auth_mode == auth_mode::sign_records) {
			r.err = verify_signature(block, r.signer);
			if(r.err) {
				return r;
			}
		}
		r = block.deserialise_record<rule_result>([this](auto const& rec) {
				// the op id survives rebases: a rebased duplicate of an already committed
				// operation is rejected even though its tag differs (plan 2.2/D6)
				if(!rec.op_id().empty() && log_.find_by_op_id(rec.op_id())) {
					return rule_result{make_error(protocol::errc::record_already_committed)};
				}
				return check_rules(rec);
			});
	} else {
		r.err = make_error(protocol::errc::record_already_committed);
	}
	return r;
}

error chain_sync::check_rules_add(data_change_record const& rec) const {
	error err;
	if(config_.mode == sync_mode::require_all_seen) {
		auto const head = log_.head();
		if(rec.last_seen_block() != head) {
			LOG_TRACE("out of sync [({},{}) != ({},{}) (rsid={})"
				, head.sequence, to_hex(head.hash), rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
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
		auto const head = log_.head();
		if(rec.last_seen_block() != head) {
			LOG_TRACE("out of sync [({},{}) != ({},{}) (rsid={})"
				, head.sequence, to_hex(head.hash), rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
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
			auto handle = log_.records().find_last(it->data.id);
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
		auto const head = log_.head();
		if(rec.last_seen_block() != head) {
			r.err = make_error(protocol::errc::record_out_of_sync);
			LOG_TRACE("out of sync [({},{}) != ({},{}) (rsid={})"
				, head.sequence, to_hex(head.hash), rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
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
		auto const head = log_.head();
		if(rec.last_seen_block() != head) {
			r.err = make_error(protocol::errc::record_out_of_sync);
			LOG_TRACE("out of sync [({},{}) != ({},{}) (rsid={})"
				, head.sequence, to_hex(head.hash), rec.last_seen_block().sequence, to_hex(rec.last_seen_block().hash), config_.log_id);
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
