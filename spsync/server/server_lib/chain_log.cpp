#include "chain_log.hpp"

#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

#include <algorithm>

namespace securepath::sync {

chain_log::chain_log(database::connection_ptr db)
: records_(db)
, head_(records_.last_block())
{
}

chain_block_id chain_log::head() const {
	return head_;
}

namespace {

/// the per record allowance on top of the content: signature, hashes, envelope, framing
std::size_t constexpr record_wire_allowance{8 * 1024};

/**
 * Size aware batching (RDS 8): keep appending while the byte budget allows, but never
 * fewer than two records. A client continues a fetch from the last record it holds, so
 * the first record of its range is one it has already: a batch of one would be that
 * record again and again whenever it and its successor exceed the budget together - a
 * range that can never be fetched. Two records are at most twice max_record_size_range.highest,
 * well inside a transport frame.
 */
void append_within_budget(std::deque<block_envelope>& out, block_envelope env, std::size_t& used, std::size_t max_bytes) {
	auto const cost = env.block().record_bytes().size() + record_wire_allowance;
	if(out.size() < 2 || used + cost <= max_bytes) {
		used += cost;
		out.push_back(std::move(env));
	}
}

}

std::deque<block_envelope> chain_log::get(sequence_number start, sequence_number end, std::size_t max,
	std::size_t max_bytes) const
{
	if(!start.is_valid()) {
		start = sequence_number{1};
	}
	if(!end.is_valid()) {
		end = head_.sequence;
	}
	std::deque<block_envelope> ret;
	std::size_t used = 0;
	// find_range skips the sequences a history cut removed (SEG 5)
	for(auto const& h : records_.find_range(start, end, record_state::in_sync, max)) {
		auto env = h->assignment();
		if(env.empty()) {
			append_within_budget(ret, block_envelope{h->record(), {}}, used, max_bytes);
		} else {
			append_within_budget(ret, serialisation::asn_der_deserialise<block_envelope>(env), used, max_bytes);
		}
	}
	return ret;
}

void chain_log::append(block_envelope const& env) {
	auto const& block = env.block();
	if(block.sequence() != head_.sequence + 1 || block.parent_hash() != head_.hash) {
		LOG_WARN("appended block does not extend the log head [({},{}) on head ({},{})]"
			, block.sequence(), to_hex(block.parent_hash()), head_.sequence, to_hex(head_.hash));
		throw make_error(sync::errc::constraint_violation, "appended block does not extend the log head");
	}
	auto handle = records_.create(block, record_state::in_sync);
	if(env.is_signed()) {
		handle->set_assignment(serialisation::asn_der_serialise(env), env.origin().data(), env.block().sequence());
	}
	head_ = block.id();
}

void chain_log::store_assignment(octet_vector const& tag, block_envelope const& env) {
	auto handle = records_.find_tag(tag);
	if(!handle) {
		throw make_error(sync::errc::constraint_violation, "storing assignment for unknown record");
	}
	// indexed by the origin so anti-entropy can serve pulls by origin sequence (plan 4.4)
	handle->set_assignment(serialisation::asn_der_serialise(env), env.origin().data(), env.block().sequence());
}

chain_block_id chain_log::origin_head(crypto::public_key_id const& origin) const {
	return records_.last_of_origin(origin.data());
}

std::deque<block_envelope> chain_log::get_by_origin(crypto::public_key_id const& origin,
	sequence_number from, sequence_number to, std::size_t max, std::size_t max_bytes) const {
	std::deque<block_envelope> ret;
	std::size_t used = 0;
	for(auto const& env : records_.find_origin_assignments(origin.data(), from, to, max)) {
		append_within_budget(ret, serialisation::asn_der_deserialise<block_envelope>(env), used, max_bytes);
	}
	return ret;
}

std::vector<chain_block> chain_log::truncate_from(sequence_number first_removed) {
	auto removed = records_.truncate_from(first_removed);
	head_ = records_.last_block();
	return removed;
}

std::vector<chain_block> chain_log::cut_before(record_tag const& segment_tag) {
	auto segment = records_.find_tag(segment_tag);
	bool const valid = segment && segment->type() == segment_record_tag
		&& segment->state() == record_state::in_sync;
	if(!valid) {
		throw make_error(sync::errc::constraint_violation, "history cut requires a committed segment as the anchor");
	}
	auto const anchor = segment->block_id().sequence;
	auto retained = records_.object_chain_tags_below(anchor);
	LOG_INFO("cutting history before the segment [anchor=({},{}), retained={}]"
		, anchor, to_hex(segment->block_id().hash), retained.size());
	return records_.truncate_prefix(anchor, retained);
}

record_handle chain_log::find_by_tag(octet_vector const& tag) const {
	return records_.find_tag(tag);
}

record_handle chain_log::find_by_op_id(octet_vector const& op_id) const {
	return records_.find_op_id(op_id);
}

sequence_number chain_log::find_divergence(std::vector<chain_block_id> peer_heads) const {
	std::ranges::sort(peer_heads, {}, &chain_block_id::sequence);
	sequence_number divergence;
	for(auto const& peer : peer_heads) {
		bool const comparable = !divergence.is_valid() && peer.sequence.is_valid()
			&& peer.sequence <= head_.sequence;
		if(comparable) {
			auto handle = records_.find(peer.sequence);
			if(!handle || handle->block_id().hash != peer.hash) {
				divergence = peer.sequence;
			}
		}
	}
	return divergence;
}

}
