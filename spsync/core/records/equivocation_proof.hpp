// SPDX-License-Identifier: MIT

#pragma once

#include "block_envelope.hpp"

namespace securepath::sync {

/**
 * Proof that an origin server assigned one sequence to two different records (plan 5.4):
 * two envelopes it signed for the storage with equal (term, sequence) and different
 * block hashes. Self-contained: anyone with the origin's key can check it. A replica
 * that found one keeps it as evidence, takes nothing of that origin's history any more
 * and tells the operator and its clients.
 */
class equivocation_proof {
public:
	equivocation_proof() = default;
	equivocation_proof(block_envelope first, block_envelope second)
	: first_(std::move(first))
	, second_(std::move(second))
	{}

	block_envelope const& first() const { return first_; }
	block_envelope const& second() const { return second_; }
	crypto::public_key_id const& origin() const { return first_.origin(); }
	std::uint64_t term() const { return first_.term(); }
	sequence_number sequence() const { return first_.block().sequence(); }

	/// both assignments are the origin's own, of one sequence, of different records
	[[nodiscard]] error verify(octet_vector const& storage_id, crypto::public_key_access const& keys) const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & first_ & second_;
	}

private:
	block_envelope first_;
	block_envelope second_;
};

}
