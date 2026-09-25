// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/divergence.hpp>
#include <spsync/core/origin_head.hpp>
#include <spsync/core/record_storage.hpp>
#include <spsync/core/records/block_envelope.hpp>

#include <securepath/database/connection.hpp>

#include <deque>
#include <limits>
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
	 * The head of the given origin in this log (plan 5.2): the newest record it assigned.
	 * For the own origin this is the last locally committed record, NOT the local head -
	 * records applied from other origins sit in between under local sequences and are not
	 * ours to announce (a peer pulling "our" sequences up to the local head would never
	 * reach it).
	 */
	chain_block_id origin_head(crypto::public_key_id const& origin) const;

	/**
	 * Get envelopes for the records [start, end], at most max entries. An invalid start
	 * defaults to the first record and an invalid end to the head.
	 */
	std::deque<block_envelope> get(sequence_number start, sequence_number end, std::size_t max,
		std::size_t max_bytes = std::numeric_limits<std::size_t>::max()) const;

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

	/**
	 * The stored assignment envelopes of one origin server with origin sequence in
	 * [from, to], in origin sequence order, at most max entries (plan 4.4 anti-entropy).
	 */
	std::deque<block_envelope> get_by_origin(crypto::public_key_id const& origin,
		sequence_number from, sequence_number to, std::size_t max,
		std::size_t max_bytes = std::numeric_limits<std::size_t>::max()) const;

	/// remove every record with sequence >= first_removed and recompute the head;
	/// returns the removed blocks (see record_storage::truncate_from)
	std::vector<chain_block> truncate_from(sequence_number first_removed);

	/**
	 * Cut the history before the given committed segment record (segments plan SEG 5/S6):
	 * removes every record below the segment except those still needed to rebuild current
	 * objects (the newest record per object id and its previous-record chain). The
	 * segment becomes the chain anchor: new clients fetch from it, verification anchors
	 * at its hash and invitees receive the hash with the invite. The head is unaffected.
	 * Throws constraint_violation when the tag is not a committed segment record.
	 *
	 * Returns the removed blocks in ascending sequence order.
	 */
	std::vector<chain_block> cut_before(record_tag const& segment_tag);

	/// find record that has the given tag
	record_handle find_by_tag(octet_vector const&) const;

	/// find record that has the given operation id (see record_base::op_id)
	record_handle find_by_op_id(octet_vector const&) const;

	/**
	 * The samples of one origin's history in this log (plan 5.3): its head and the
	 * exponentially spaced records behind it that this log holds, by origin sequence.
	 * Empty for an origin without records here.
	 */
	origin_samples samples_of(crypto::public_key_id const& origin) const;

	/**
	 * Where this log's view of the origin parts from a peer's samples of it (plan 5.3):
	 * the newest sample held under the same hash, the oldest held under a different one.
	 * A peer ahead of us on the origin is not divergence, we are only behind.
	 */
	divergence find_divergence(origin_samples const&) const;

	record_storage& records() { return records_; }
	record_storage const& records() const { return records_; }

private:
	record_storage records_;
	chain_block_id head_;
};

}
