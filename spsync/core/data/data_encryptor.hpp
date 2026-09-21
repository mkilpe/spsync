#pragma once

#include "data_descriptor.hpp"
#include "data_manifest.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <securepath/crypto/hash.hpp>

#include <functional>

namespace securepath::sync {

/// what the encryptor produced: the two descriptor halves for the record and the manifest for the upload
struct encrypted_data_result {
	data_descriptor descriptor;
	data_header header;
	data_manifest manifest;
};

/**
 * Turns a plaintext stream into encrypted chunks (RD3) with the size-class padding of
 * RD11 applied inside the ciphertext. Feed the plaintext with write() in any pieces,
 * every completed chunk goes to the sink as it is ready (so a multi-gigabyte source is
 * never held in memory), finish() pads, flushes the last chunk and returns the
 * descriptor. The data key is derived from the group key and a fresh nonce.
 */
class data_encryptor {
public:
	using chunk_sink = std::function<void(std::uint64_t chunk_no, octet_vector const& encrypted)>;

	data_encryptor(encryption_key const& group_key, std::uint32_t chunk_size, chunk_sink sink);

	/**
	 * With the nonce of an existing data instead of a fresh one: the same plaintext gives
	 * the same chunks again, so a data whose content is held under another data id can be
	 * rebuilt locally and checked against its manifest digest instead of downloaded. Never
	 * for new data: a nonce is used for one content only.
	 */
	data_encryptor(encryption_key const& group_key, std::uint32_t chunk_size, chunk_sink sink, octet_vector nonce);

	/// append plaintext
	void write(octet_span plain);

	/// pad, flush and describe; call once after the last write
	encrypted_data_result finish();

	/// the nonce chosen for this data
	octet_vector const& nonce() const { return nonce_; }

private:
	void consume(octet_span bytes);
	void emit_chunk(octet_span plain);
	void pad();

private:
	octet_vector nonce_;
	octet_vector data_key_;
	std::uint32_t chunk_size_{};
	sequence_number key_seq_;
	chunk_sink sink_;
	octet_vector buffer_;
	crypto::hash_stream content_hash_;
	data_manifest manifest_;
	std::uint64_t plain_size_{};
	std::uint64_t enc_size_{};
	std::uint64_t chunks_{};
};

}
