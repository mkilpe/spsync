// SPDX-License-Identifier: MIT

#pragma once

#include "data_descriptor.hpp"

#include <spsync/core/encryption_key_storage.hpp>

#include <optional>

namespace securepath::sync {

/**
 * Reads the chunks a data_encryptor produced: any chunk on its own (random access,
 * RD3), verified by its tag, with the RD11 padding stripped using the true length
 * from the encrypted header. The content digest is the reader's to check once it has
 * read everything (crypto::hash_stream over the returned plaintext).
 */
class data_decryptor {
public:
	data_decryptor(encryption_key const& group_key, data_descriptor descriptor, data_header header);

	std::uint64_t chunk_count() const { return descriptor_.chunk_count(); }

	/// bytes of the data in that chunk (the padding excluded); 0 for an all-padding chunk
	std::uint64_t chunk_plain_size(std::uint64_t chunk_no) const;

	/// the data bytes of one encrypted chunk, nullopt when it does not authenticate or is mis-sized
	std::optional<octet_vector> decrypt(std::uint64_t chunk_no, octet_span encrypted) const;

	data_descriptor const& descriptor() const { return descriptor_; }
	data_header const& header() const { return header_; }

private:
	data_descriptor descriptor_;
	data_header header_;
	octet_vector data_key_;
};

}
