#pragma once

#include <spsync/core/chain_block_id.hpp>

#include <securepath/crypto/public_key_id.hpp>

#include <cstdint>

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

}
