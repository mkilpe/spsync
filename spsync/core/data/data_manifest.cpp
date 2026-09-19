#include "data_manifest.hpp"
#include "chunk_crypto.hpp"

#include <spsync/core/sync_mode.hpp>

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

bool valid_data_descriptor(data_descriptor const& d) {
	bool const chunking_ok = d.chunk_size >= min_chunk_size && d.chunk_size <= max_chunk_size;
	return chunking_ok && d.manifest_digest.size() == crypto::hash_digest_size()
		&& d.enc_size > chunk_tag_size() && d.chunk_count() <= max_data_chunks;
}

std::uint64_t data_descriptor::chunk_enc_size(std::uint64_t chunk_no) const {
	std::uint64_t ret = 0;
	if(chunk_no < chunk_count()) {
		std::uint64_t const per_chunk = chunk_size + chunk_tag_size();
		ret = std::min<std::uint64_t>(per_chunk, enc_size - chunk_no * per_chunk);
	}
	return ret;
}

std::uint64_t data_descriptor::chunk_count() const {
	std::uint64_t ret = 0;
	if(chunk_size != 0) {
		std::uint64_t const per_chunk = chunk_size + chunk_tag_size();
		ret = (enc_size + per_chunk - 1) / per_chunk;
	}
	return ret;
}

}
