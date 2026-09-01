#include "history_verifier.hpp"
#include "record_verifier.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/record_storage.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::sync {
namespace {

/**
 * The stored blob of an own committed record keeps its pre-assignment sequence and
 * parent hash (defect B8, only the columns carry the server assigned values), so the
 * committed block is reconstructed from the blob content plus the stored columns; for
 * records received from the server this is a no-op.
 */
chain_block committed_block(record_handle const& h) {
	auto block = h->record();
	block.set_sequence_and_parent_hash(h->block_id().sequence, h->parent_block_hash());
	return block;
}

error check_stored_hash(record_handle const& h, chain_block const& block) {
	error err;
	if(block.hash() != h->block_id().hash) {
		LOG_WARN("stored record hash does not match the content [seq={}, tag={}]"
			, h->block_id().sequence, to_hex(h->tag()));
		err = make_error(sync::errc::not_authentic, "stored record hash does not match the content");
	}
	return err;
}

/// authenticate one record, counting it into the report
error verify_record(encryption_key_storage const& keys, chain_block const& block, history_verify_report& report) {
	return block.deserialise_record<error>([&](auto const& rec) {
			auto key = keys.find(rec.encryption_key());
			if(!key) {
				return make_error(sync::errc::no_encryption_key_found, "no encryption key for record");
			}
			record_verifier<std::decay_t<decltype(rec)>> ver(*key, rec, block.auth());
			if(!ver.is_authentic()) {
				return make_error(sync::errc::not_authentic, "record is not authentic");
			}
			if constexpr(std::is_same_v<std::decay_t<decltype(rec)>, segment_record>) {
				++report.verified_segments;
			} else {
				++report.verified_records;
			}
			return error{};
		});
}

/// verify [first, last] fully: recomputed hashes, parent links and authenticity
error verify_range(record_storage const& records, encryption_key_storage const& keys
	, sequence_number first, sequence_number last, octet_vector parent, history_verify_report& report) {
	error err;
	for(auto seq = first; !err && seq <= last; ++seq) {
		auto h = records.find(seq);
		if(!h) {
			err = make_error(sync::errc::invalid_record_chain_state, "missing record in the chain");
		} else {
			auto block = committed_block(h);
			err = check_stored_hash(h, block);
			if(!err && block.parent_hash() != parent) {
				LOG_WARN("record does not link to the previous block [seq={}]", seq);
				err = make_error(sync::errc::invalid_record_chain_state, "record does not link to the previous block");
			}
			if(!err) {
				err = verify_record(keys, block, report);
				parent = block.hash();
			}
		}
	}
	return err;
}

util::result<history_verify_report> full_verify(record_storage const& records, encryption_key_storage const& keys) {
	history_verify_report report;
	auto err = verify_range(records, keys, sequence_number{1}, records.last_block().sequence, {}, report);
	if(err) {
		return err;
	}
	return report;
}

/// one backbone entry: the coverage list must match the stored records of its range
error check_segment_coverage(record_storage const& records, plain_segment_data const& data
	, sequence_number expected_end, history_verify_report& report) {
	if(data.segment_start() >= data.segment_end()) {
		return make_error(sync::errc::invalid_record_chain_state, "segment covers an empty range");
	}
	if(expected_end.is_valid() && data.segment_end() != expected_end) {
		return make_error(sync::errc::invalid_record_chain_state, "segment backbone is not continuous");
	}
	if(data.tags() != records.tags_in_range(data.segment_start(), data.segment_end() - 1)) {
		LOG_WARN("stored records do not match the segment coverage [start={}, end={}]"
			, data.segment_start(), data.segment_end());
		return make_error(sync::errc::not_authentic, "stored records do not match the segment coverage");
	}
	report.covered_records += data.tags().size();
	return {};
}

/// step to the previous segment along the backbone; a cleared handle ends the walk
error next_backbone_segment(record_storage const& records, plain_segment_data const& data, record_handle& handle) {
	handle = {};
	if(!data.previous_segment_tag().empty()) {
		handle = records.find_tag(data.previous_segment_tag());
		bool const valid = handle && handle->type() == segment_record_tag
			&& handle->state() == record_state::in_sync;
		if(!valid) {
			handle = {};
			return make_error(sync::errc::invalid_record_chain_state, "segment backbone is broken");
		}
	} else if(data.segment_start() != sequence_number{1}) {
		return make_error(sync::errc::invalid_record_chain_state, "backbone does not cover the chain start");
	}
	return {};
}

/**
 * Verify [boundary, head] fully, anchored on the last covered record's stored hash;
 * the newest segment record itself sits inside this range.
 */
error verify_tail(record_storage const& records, encryption_key_storage const& keys
	, sequence_number boundary, history_verify_report& report) {
	auto before = records.find(boundary - 1);
	if(!before) {
		return make_error(sync::errc::invalid_record_chain_state, "missing record in the chain");
	}
	return verify_range(records, keys, boundary, records.last_block().sequence
		, before->block_id().hash, report);
}

/**
 * Walk the backbone from the newest segment: authenticate every segment below the
 * boundary (the ones at or past it were verified with the tail) and check each
 * coverage list against the stored records.
 */
error verify_backbone(record_storage const& records, encryption_key_storage const& keys
	, record_handle handle, sequence_number boundary, history_verify_report& report) {
	error err;
	std::size_t walked{};
	sequence_number expected_end;
	while(!err && handle) {
		auto block = committed_block(handle);
		auto const data = block.deserialise_to<segment_record>().data();
		if(handle->block_id().sequence < boundary) {
			err = check_stored_hash(handle, block);
			if(!err) {
				err = verify_record(keys, block, report);
				++walked;
			}
		}
		if(!err) {
			err = check_segment_coverage(records, data, expected_end, report);
		}
		if(!err) {
			expected_end = data.segment_start();
			err = next_backbone_segment(records, data, handle);
		}
	}
	if(!err) {
		// the walked segments are inside a later segment's list: keep the counters disjoint
		report.covered_records -= walked;
	}
	return err;
}

util::result<history_verify_report> fast_verify(record_storage const& records, encryption_key_storage const& keys) {
	auto newest = records.find_last_of_type(segment_record_tag);
	if(!newest) {
		// nothing to anchor on
		return full_verify(records, keys);
	}
	history_verify_report report;
	auto const boundary = newest->record().deserialise_to<segment_record>().data().segment_end();
	auto err = verify_tail(records, keys, boundary, report);
	if(!err) {
		err = verify_backbone(records, keys, newest, boundary, report);
	}
	if(err) {
		return err;
	}
	return report;
}

}

util::result<history_verify_report> verify_history(record_storage const& records
	, encryption_key_storage const& keys, history_verification mode) {
	try {
		if(mode == history_verification::full) {
			return full_verify(records, keys);
		}
		return fast_verify(records, keys);
	} catch(error const& err) {
		return err;
	} catch(std::exception const& exp) {
		LOG_WARN("exception while verifying history [exp={}]", exp.what());
		return make_error(securepath::errc::exception_occurred);
	}
}

}
