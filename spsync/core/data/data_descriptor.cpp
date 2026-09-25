// SPDX-License-Identifier: MIT

#include "data_descriptor.hpp"
#include "chunk_crypto.hpp"

#include <spsync/core/sync_mode.hpp>

#include <securepath/crypto/hash.hpp>

#include <algorithm>

namespace securepath::sync {

bool usable_data_descriptor(data_descriptor const& d) {
	auto const chunks = d.chunk_count();
	return !d.manifest_digest.empty() && chunks >= 1 && chunks <= max_data_chunks
		&& d.chunk_enc_size(chunks - 1) > chunk_tag_size();
}

bool valid_data_descriptor(data_descriptor const& d) {
	bool const chunking_ok = d.chunk_size >= chunk_size_range.lowest && d.chunk_size <= chunk_size_range.highest;
	return chunking_ok && d.manifest_digest.size() == crypto::hash_digest_size() && usable_data_descriptor(d);
}

std::uint64_t data_descriptor::chunk_enc_size(std::uint64_t chunk_no) const {
	std::uint64_t ret = 0;
	if(chunk_no < chunk_count()) {
		std::uint64_t const per_chunk = std::uint64_t{chunk_size} + chunk_tag_size();
		// chunk_no < chunk_count: the product is below enc_size
		ret = std::min<std::uint64_t>(per_chunk, enc_size - chunk_no * per_chunk);
	}
	return ret;
}

bool data_descriptor::chunk_holds_range(std::uint64_t chunk_no, std::uint64_t offset, std::uint64_t size) const {
	auto const chunk = chunk_enc_size(chunk_no);
	return offset <= chunk && size <= chunk - offset;
}

std::uint64_t data_descriptor::chunk_count() const {
	std::uint64_t ret = 0;
	if(chunk_size != 0) {
		// enc_size is whatever the wire said: rounded up without adding to it
		std::uint64_t const per_chunk = std::uint64_t{chunk_size} + chunk_tag_size();
		ret = enc_size / per_chunk + (enc_size % per_chunk != 0 ? 1 : 0);
	}
	return ret;
}

}
