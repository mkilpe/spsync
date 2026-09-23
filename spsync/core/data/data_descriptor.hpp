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

	/// true when [offset, offset + size) lies inside the given encrypted chunk. The values
	/// come from the wire as they are: nothing here wraps
	bool chunk_holds_range(std::uint64_t chunk_no, std::uint64_t offset, std::uint64_t size) const;

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

/// the most chunks a data may have: its manifest must fit one transport frame
std::uint64_t constexpr max_data_chunks{200000};

/**
 * The bounds every replica judges a descriptor by (RD10: a validity rule, so it is
 * deterministic and states nothing about the data itself, which the record servers never
 * see): a sha3-512 manifest digest, a chunk size within chunk_size_range (sync_mode.hpp)
 * - every data is self-describing, it need not be the storage's default - and a size
 * that makes at least one and at most max_data_chunks chunks.
 */
[[nodiscard]] bool valid_data_descriptor(data_descriptor const&);

/**
 * What any holder can work with, whoever vouched for the descriptor: a data id, a chunk
 * size, at least one and at most max_data_chunks chunks, and a last chunk that is more
 * than its tag (anything less can never decrypt). Part of valid_data_descriptor; on its
 * own the guard of the places that size a bitmap or a manifest from a descriptor.
 */
[[nodiscard]] bool usable_data_descriptor(data_descriptor const&);

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
