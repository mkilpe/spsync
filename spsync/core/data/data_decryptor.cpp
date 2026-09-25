// SPDX-License-Identifier: MIT

#include "data_decryptor.hpp"
#include "chunk_crypto.hpp"

#include <algorithm>

namespace securepath::sync {

data_decryptor::data_decryptor(encryption_key const& group_key, data_descriptor descriptor, data_header header)
: descriptor_(std::move(descriptor))
, header_(std::move(header))
, data_key_(derive_data_key(group_key.key, header_.nonce))
{
}

std::uint64_t data_decryptor::chunk_plain_size(std::uint64_t chunk_no) const {
	std::uint64_t ret = 0;
	std::uint64_t const start = chunk_no * descriptor_.chunk_size;
	if(start < header_.plain_size) {
		ret = std::min<std::uint64_t>(header_.plain_size - start, descriptor_.chunk_size);
	}
	return ret;
}

std::optional<octet_vector> data_decryptor::decrypt(std::uint64_t chunk_no, octet_span encrypted) const {
	std::optional<octet_vector> ret;
	if(chunk_no < chunk_count()) {
		ret = decrypt_chunk(data_key_, header_.nonce, chunk_no, encrypted);
		if(ret) {
			std::uint64_t const keep = chunk_plain_size(chunk_no);
			if(ret->size() < keep) {
				// shorter than the length the header promises: not this data's chunk
				ret.reset();
			} else {
				ret->resize(keep);
			}
		}
	}
	return ret;
}

}
