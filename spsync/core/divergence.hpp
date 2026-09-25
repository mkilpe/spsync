// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/chain_block_id.hpp>

#include <functional>
#include <vector>

namespace securepath::sync {

/**
 * Where two servers' views of one origin's history part (plan 5.3), as far as the
 * samples of one of them tell against the log of the other: the newest sample the log
 * holds under the same hash and the oldest it holds under a different one. The fork
 * lies between them; adjacent bounds name it exactly, wider ones call for samples in
 * between (the binary search over the peer's history). Neither is set when the samples
 * touch nothing the log holds.
 */
struct divergence {
	/// the histories conflict: a sequence held under different hashes
	bool diverged() const {
		return first_divergent.is_valid();
	}

	/// the fork is pinned to one sequence: nothing lies between the bounds
	bool exact() const {
		return diverged() && last_common + 1 == first_divergent;
	}

	bool operator==(divergence const&) const = default;

public:
	sequence_number last_common;
	sequence_number first_divergent;
};

/**
 * The sequences to sample behind a head: the head, then 1, 2, 4, 8, ... behind it and
 * the first record, newest first. About log2(head) of them - enough to place a fork
 * within a factor of two of its sequence with one exchange.
 */
std::vector<sequence_number> sample_sequences(sequence_number head);

/// what a log holds at a sequence of the sampled history: the block hash, empty for nothing
using held_hash = std::function<octet_vector(sequence_number)>;

/**
 * The divergence the samples show against a log. Samples the log does not hold are
 * neither common nor divergent: a history cut removed them, or the log is behind.
 */
divergence find_divergence(std::vector<chain_block_id> const& samples, held_hash const& held);

/// what anti-entropy pulls of one origin from a peer (plan 4.4 with 5.3): nothing when
/// the peer has nothing new or the histories conflict
struct pull_range {
	bool wanted() const {
		return from.is_valid();
	}

	bool operator==(pull_range const&) const = default;

public:
	sequence_number from;
	sequence_number to;
};

/**
 * The range to pull: after the newest record we hold of the origin - the stored head or
 * the newest common sample, whichever is further - up to the peer's head. Nothing when
 * the peer's head is not beyond that, or when the histories diverge: the pull would
 * bring records that conflict with held ones (evidence, plan 5.4).
 */
pull_range plan_pull(sequence_number known, sequence_number peer_head, divergence const&);

/**
 * What a pushed record of an origin (plan 4.2) calls for: nothing when it is the next
 * record after the highest one held of the origin (or one held already) - it is taken
 * as it is. A record further ahead may have records of the origin before it that never
 * arrived (a push while the connection was down, a push racing a bootstrap pull): taken,
 * it would move the held head past them and anti-entropy, which pulls from the head,
 * would never ask for them. So it is pulled instead, from the head up to it, and the
 * pull applies the records in the origin's order. An origin's sequences may skip (the
 * local positions of records it applied from others): the pull then brings the pushed
 * record alone.
 */
pull_range plan_push(sequence_number known, sequence_number pushed);

}
