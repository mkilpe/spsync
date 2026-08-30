#pragma once

#include <spsync/core/record_storage.hpp>
#include <spsync/core/records/block_envelope.hpp>

#include <securepath/database/connection.hpp>

#include <deque>
#include <vector>

namespace securepath::sync {

/**
 * Server side log over block envelopes (plan 3.2). Owns the record storage and the chain
 * head; the validation rules stay in chain_sync. Weak and strict replication both talk to
 * this type and the Raft state machine adapter (6.2) is a thin wrapper on it.
 *
 * Records appended without a signature (no server signing key) are returned as unsigned
 * envelopes wrapping the stored block.
 */
class chain_log {
public:
	explicit chain_log(database::connection_ptr);

	/// id of the last block in the log
	chain_block_id head() const;

	/**
	 * Get envelopes for the records [start, end], at most max entries. An invalid start
	 * defaults to the first record and an invalid end to the head.
	 */
	std::deque<block_envelope> get(sequence_number start, sequence_number end, std::size_t max) const;

	/**
	 * Append the envelope's block as the new head. The block must extend the head
	 * (sequence and parent hash), otherwise constraint_violation is thrown. A signed
	 * envelope is persisted with the record.
	 */
	void append(block_envelope const&);

	/**
	 * Persist the signed assignment for an already appended record; the local commit path
	 * signs only after the sequence is assigned. Throws constraint_violation for an
	 * unknown record.
	 */
	void store_assignment(octet_vector const& tag, block_envelope const&);

	/// remove every record with sequence >= first_removed and recompute the head;
	/// returns the removed blocks (see record_storage::truncate_from)
	std::vector<chain_block> truncate_from(sequence_number first_removed);

	/// find record that has the given tag
	record_handle find_by_tag(octet_vector const&) const;

	/// find record that has the given operation id (see record_base::op_id)
	record_handle find_by_op_id(octet_vector const&) const;

	/**
	 * The lowest sequence at which this log disagrees with the given peer heads: a head
	 * whose sequence we hold under a different hash. A peer sequence beyond our head is
	 * not divergence (we are only behind). Returns an invalid sequence when there is none.
	 */
	sequence_number find_divergence(std::vector<chain_block_id> peer_heads) const;

	record_storage& records() { return records_; }
	record_storage const& records() const { return records_; }

private:
	record_storage records_;
	chain_block_id head_;
};

}
