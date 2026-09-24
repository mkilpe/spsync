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

octet_vector data_manifest::octets() const {
	octet_vector ret;
	ret.reserve(chunk_digests.size() * crypto::hash_digest_size());
	for(auto const& d : chunk_digests) {
		ret.insert(ret.end(), d.begin(), d.end());
	}
	return ret;
}

std::optional<data_manifest> data_manifest::from_octets(octet_span octets) {
	std::optional<data_manifest> ret;
	auto const size = crypto::hash_digest_size();
	if(octets.size() % size == 0) {
		data_manifest m;
		for(std::size_t pos = 0; pos != octets.size(); pos += size) {
			m.chunk_digests.emplace_back(octets.begin() + static_cast<std::ptrdiff_t>(pos), octets.begin() + static_cast<std::ptrdiff_t>(pos + size));
		}
		ret = std::move(m);
	}
	return ret;
}

}
