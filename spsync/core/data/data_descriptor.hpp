#pragma once

#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * The server-visible half of a record data descriptor (RD2): part of the authenticated
 * plain single change. It leaks sizes only and lets a server verify stored chunks
 * without decrypting: the manifest (ordered chunk digests) must hash to
 * manifest_digest and every chunk to its manifest entry. data_id := manifest_digest.
 */
struct data_descriptor {
	/// number of encrypted chunks: each carries a GCM tag, the last one may be short
	std::uint64_t chunk_count() const;

	/// size of the given encrypted chunk incl. its tag; 0 past the end
	std::uint64_t chunk_enc_size(std::uint64_t chunk_no) const;

	bool operator==(data_descriptor const&) const = default;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & enc_size & chunk_size & manifest_digest & trailing_data;
	}

public:
	/// total size of the encrypted chunks incl. their tags (padded, RD11); quota counts this
	std::uint64_t enc_size{};

	/// plaintext bytes per chunk used for this data (every data is self-describing)
	std::uint32_t chunk_size{};

	/// sha3-512 over the ordered chunk digests
	octet_vector manifest_digest;

	serialisation::trailing_data trailing_data;
};

/// the stable identity of a data: its manifest digest (RD2/RD7)
using data_id = octet_vector;

/**
 * The members-only half of the descriptor (RD2/RD3), inside the encrypted header:
 * what a reader needs to derive the data key, strip the padding and verify the content.
 */
struct data_header {
	bool operator==(data_header const&) const = default;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & plain_size & content_digest & nonce & key_seq & flags & trailing_data;
	}

public:
	/// true plaintext length; the chunks hold the size-class padded length (RD11)
	std::uint64_t plain_size{};

	/// sha3-512 of the plaintext (end-to-end integrity, local dedup)
	octet_vector content_digest;

	/// per-data nonce: salt of the data key derivation and part of every chunk's AAD
	octet_vector nonce;

	/// sequence of the group encryption key the data key derives from
	sequence_number key_seq;

	/// reserved (compression), must be 0
	std::uint32_t flags{};

	serialisation::trailing_data trailing_data;
};

}
