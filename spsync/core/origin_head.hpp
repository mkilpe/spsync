// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/chain_block_id.hpp>

#include <securepath/crypto/public_key_id.hpp>

#include <cstdint>
#include <vector>

namespace securepath::sync {

/// The highest block seen from one origin server: what anti-entropy exchanges (plan 3.4/4.1)
struct origin_head {
	crypto::public_key_id origin;
	/// consensus term of the head block; stays 0 until phase 6
	std::uint64_t term{};
	chain_block_id block;

	bool operator==(origin_head const&) const = default;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & origin & term & block;
	}
};

/**
 * Samples of one origin's history as a server holds it (plan 5.3): the head and
 * exponentially spaced blocks behind it, newest first (divergence.hpp), so a peer can
 * place where its view of the origin parts from this one with one exchange.
 */
struct origin_samples {
	crypto::public_key_id origin;
	std::vector<chain_block_id> blocks;

	bool operator==(origin_samples const&) const = default;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & origin & blocks;
	}
};

}
