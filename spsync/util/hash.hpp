#ifndef SPSYNC_UTIL_HASH_HEADER
#define SPSYNC_UTIL_HASH_HEADER

#include <securepath/crypto/hash.hpp>
#include <securepath/serialisation/types.hpp>

namespace securepath::sync::util {

/**
 * Contains hash value and the hash algorithm id.
 */
struct hash {
	crypto::hash_algorithm id{crypto::hash_algorithm::sha3_512};
	octet_vector digest;
	serialisastion::trailing_data trailing_data

	template<typename Ar>
	void serialise(Ar& ar) {
		serialiation::sequence<Ar> seq(ar);
		seq & id & digest & trailing_data;
	}
};

#endif