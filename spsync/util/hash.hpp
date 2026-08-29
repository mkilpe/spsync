#pragma once

#include <securepath/crypto/hash.hpp>
#include <securepath/serialisation/types.hpp>

namespace securepath::sync::util {

/**
 * Contains hash value and the hash algorithm id.
 */
struct hash {
	crypto::hash_algorithm id{crypto::hash_algorithm::sha3_512};
	octet_vector digest;
	serialisation::trailing_data trailing_data

	bool is_valid() const {
		return !digest.empty();
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialiation::sequence<Ar> seq(ar);
		seq & id & digest & trailing_data;
	}
};


