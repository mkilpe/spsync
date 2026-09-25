// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/types.hpp>

#include <optional>

namespace securepath::sync {

/// size of the per-data nonce (RD3)
std::size_t constexpr data_nonce_size = 16;

/// data key (RD3): HKDF-SHA3-512 over the group key, salted with the per-data nonce
octet_vector derive_data_key(octet_vector const& group_key, octet_vector const& nonce);

/// GCM iv of a chunk: the chunk counter; unique per data key
octet_vector chunk_iv(std::uint64_t chunk_no);

/// additional authenticated data of a chunk: nonce + chunk number (no reorder, no transplant)
octet_vector chunk_aad(octet_vector const& nonce, std::uint64_t chunk_no);

/// AES-256-GCM of one chunk; the tag is appended to the ciphertext
octet_vector encrypt_chunk(octet_vector const& data_key, octet_vector const& nonce, std::uint64_t chunk_no, octet_span plain);

/// the plaintext of one encrypted chunk, nullopt when it does not authenticate
std::optional<octet_vector> decrypt_chunk(octet_vector const& data_key, octet_vector const& nonce, std::uint64_t chunk_no, octet_span encrypted);

/// sha3-512 of an encrypted chunk (the manifest entry)
octet_vector chunk_digest(octet_span encrypted);

/// size of the tag each encrypted chunk carries
std::size_t chunk_tag_size();

}
