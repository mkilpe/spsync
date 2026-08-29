#pragma once

#include "chain_block.hpp"

#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/public_key_access.hpp>
#include <securepath/crypto/public_key_id.hpp>
#include <securepath/crypto/signature.hpp>

namespace securepath::sync {

/**
 * The server's replication metadata around a chain block (plan D7/2.5): who assigned the
 * sequence and a signature over the assignment. Two envelopes from the same origin with
 * equal (storage, term, sequence) and different block hashes are self-contained proof of
 * equivocation. term stays 0 until the consensus work (phase 6).
 */
class block_envelope {
public:
	block_envelope() = default;
	block_envelope(chain_block block, crypto::public_key_id origin, std::uint64_t term = 0)
	: block_(std::move(block))
	, origin_(std::move(origin))
	, term_(term)
	{}

	chain_block const& block() const { return block_; }
	crypto::public_key_id const& origin() const { return origin_; }
	std::uint64_t term() const { return term_; }
	bool is_signed() const { return signature_.is_valid(); }

	/// sign the assignment (storage, origin, term, sequence, block hash) with the server key
	void sign(octet_vector const& storage_id, crypto::private_key const& key);

	/// verify the assignment signature; also checks that the signer is the stated origin
	error verify(octet_vector const& storage_id, crypto::public_key_access const& keys) const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & block_ & origin_ & term_ & signature_ & trailing_data_;
	}

private:
	octet_vector assignment_digest(octet_vector const& storage_id) const;

private:
	chain_block block_;
	crypto::public_key_id origin_;
	std::uint64_t term_{};
	crypto::signature signature_;
	serialisation::trailing_data trailing_data_;
};

}

