#include "data_manifest.hpp"
#include "chunk_crypto.hpp"

#include <securepath/crypto/hash.hpp>

#include <algorithm>

namespace securepath::sync {

octet_vector data_manifest::digest() const {
	crypto::hash_stream h;
	for(auto const& d : chunk_digests) {
		h.update(d);
	}
	return h.final();
}

bool data_manifest::matches(data_descriptor const& d) const {
	return chunk_digests.size() == d.chunk_count() && digest() == d.manifest_digest;
}

bool data_manifest::verify_chunk(std::uint64_t chunk_no, octet_span encrypted) const {
	return chunk_no < chunk_digests.size() && chunk_digests[chunk_no] == chunk_digest(encrypted);
}

}
