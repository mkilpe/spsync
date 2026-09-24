#pragma once

#include "data_encryptor.hpp"
#include "data_state_table.hpp"

#include <spsync/core/record_data.hpp>

#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace securepath::sync {

class record_data_store_impl;

/**
 * Creates a data locally (RD7): feed the plaintext with write() in any pieces, the
 * encrypted chunks go to the store's staging area as they complete, finish() moves
 * them under the data id and registers the data as upload_pending with everything
 * held and the manifest known. A writer dropped before finish() leaves nothing behind.
 */
class data_writer {
public:
	data_writer(std::shared_ptr<record_data_store_impl>, encryption_key const& group_key, std::uint32_t chunk_size);
	data_writer(data_writer&&) noexcept;
	~data_writer();

	/// append plaintext
	void write(octet_span plain);

	/// register the data; the descriptor halves go into the record. Call once.
	encrypted_data_result finish();

private:
	std::shared_ptr<record_data_store_impl> store_;
	std::string stage_;
	std::unique_ptr<data_encryptor> encryptor_;
};

/**
 * A chunk on its way in, piece by piece (a transfer never moves a whole chunk in one
 * packet, see protocol/data_protocol.hpp): the pieces are appended to a staged file and
 * hashed as they come, so nothing but the piece at hand is in memory. finish() checks the
 * whole against the manifest and only then makes it a chunk of the data. Dropped before
 * that - a lost connection - it leaves nothing behind: resuming is per chunk.
 */
class incoming_chunk {
public:
	incoming_chunk(std::shared_ptr<record_data_store_impl>, data_id, std::uint64_t chunk_no
		, std::uint64_t expected_size, octet_vector expected_digest);
	incoming_chunk(incoming_chunk&&) noexcept;
	~incoming_chunk();

	std::uint64_t chunk_no() const { return chunk_no_; }

	/// octets so far: the offset the next piece must have
	std::uint64_t received() const { return received_; }

	/// octets of the whole chunk: what its staged file takes when it is in
	std::uint64_t expected_size() const { return expected_size_; }

	/// every octet of the chunk arrived
	bool complete() const { return received_ == expected_size_; }

	/// the next piece; false when it is not the next one or overruns the chunk - the
	/// chunk is lost then, it starts over with a new incoming_chunk
	bool append(std::uint64_t offset, octet_span piece);

	/// keep the chunk when it is complete and the one the manifest names; call once
	bool finish();

private:
	void discard();

private:
	std::shared_ptr<record_data_store_impl> store_;
	data_id id_;
	std::uint64_t chunk_no_{};
	std::uint64_t expected_size_{};
	octet_vector expected_digest_;
	std::string stage_;
	crypto::hash_stream hash_;
	std::uint64_t received_{};
	bool open_{};
};

/**
 * Stream a whole source into a writer in pieces, never holding more than one piece
 * (RD7: "stream the source once"). Throws when the source ends before its size().
 */
void copy_record_data(record_data& source, data_writer& writer);

/// a data held completely, as the content index knows it
struct held_content {
	data_descriptor descriptor;
	data_header header;
};

/**
 * The client data store (RD6): record data as encrypted chunk files (chunk_files)
 * plus the data table (data_state_table) in the storage database. Data is identified
 * by its data_id and shared by every record naming it; the record storage counts the
 * references (record_storage::data_reference_count).
 *
 * The store never sees plaintext at rest: a writer encrypts on the way in, a handle
 * from open() decrypts chunk-wise on the way out, the transfer side (manifest, chunks)
 * moves ciphertext only and verifies it against the manifest the record commits to.
 *
 * Thread safe; handles and writers keep the store's internals alive.
 */
class record_data_store {
public:
	/// data_root is the directory of the chunk files, e.g. record-storages/<sid>/data
	record_data_store(database::connection_ptr, std::filesystem::path data_root);

	// -- local use --

	/// start a locally created data
	data_writer create(encryption_key const& group_key, std::uint32_t chunk_size);

	/**
	 * Reader of a data. The key candidates are the group keys stored for the header's
	 * key sequence (colliding rotations keep several, D9); the one that authenticates
	 * is found on the first chunk read. Null when the descriptor contradicts what is
	 * known of the data id: that record's data is invalid.
	 */
	record_data_handle open(std::vector<encryption_key> const& group_keys, data_descriptor const&, data_header const&);

	/// what is known of the data, nullopt when no record or writer named it
	std::optional<data_state_row> find(data_id const&) const;

	/**
	 * A data held completely whose content has the digest, other than the named one: the
	 * same content was sent under another data id (another nonce or key). Known for data
	 * that was created here or opened once - the digest is in the members-only header.
	 */
	std::optional<held_content> find_content(octet_vector const& content_digest, data_id const& other_than) const;

	/**
	 * Make the wanted data out of a source with the same content instead of downloading
	 * it: the source is encrypted again with the wanted data's nonce and the group key,
	 * which gives the same chunks when key and content are the right ones - only then,
	 * checked against the descriptor's manifest digest, the data is held (in_sync). False
	 * and nothing changed otherwise (try another key candidate, or download).
	 */
	bool adopt_content(record_data& source, encryption_key const& group_key, data_descriptor const& wanted, data_header const& wanted_header);

	void set_state(data_id const&, record_data_state);

	/**
	 * Drop the local chunks (state removed, refetchable), the row and the manifest stay.
	 * Refused (false) for an unknown data and while upload_pending: the chunks may be
	 * the only copy.
	 */
	bool evict(data_id const&);

	/**
	 * The retention policy of the storage let the data go (record_data.txt RD9, state
	 * pruned): the local chunks are dropped whatever the state - the caller decides, a
	 * data still to be uploaded included - the row and the manifest stay with the record
	 * that names it. False for an unknown data. Asking for it again is possible as long
	 * as a server has it; a new record naming it makes it deferred again.
	 */
	bool prune(data_id const&);

	/**
	 * Drop these data, rows and chunks (RD9): what no stored record references any more
	 * (record_storage::unreferenced_data), what a server was told to let go. Unknown ids
	 * are nothing; returns how many were known.
	 */
	std::size_t remove(std::vector<data_id> const&);

	// -- transfer side, ciphertext only --

	/// keep the manifest of a known data; false when it is not the one the descriptor commits to
	bool set_manifest(data_id const&, data_manifest const&);

	/**
	 * Make a data known by descriptor and manifest in one step (a data server learns of a
	 * data from a ticket, not from a record): the row as deferred with nothing held when
	 * it is new. Nullopt when the manifest is not the descriptor's or the descriptor
	 * contradicts what is known of the data id.
	 */
	std::optional<data_state_row> register_data(data_descriptor const&, data_manifest const&);

	/// the same by the descriptor alone: the manifest comes with the download (a data
	/// server that is to hold a copy, RD13). Nullopt when the descriptor contradicts what
	/// is known of the data id.
	std::optional<data_state_row> register_data(data_descriptor const&);

	std::optional<data_manifest> manifest(data_id const&) const;
	/// the manifest is known: what an upload needs before its chunks; cheaper than the manifest
	bool has_manifest(data_id const&) const;

	/**
	 * Keep a received chunk: it must be the one the manifest names, so the manifest
	 * comes first. The last missing chunk flips the data to in_sync. False when the
	 * chunk does not verify.
	 */
	bool store_chunk(data_id const&, std::uint64_t chunk_no, octet_span encrypted);

	/**
	 * Start receiving a chunk in pieces. Nullopt when the data has no manifest yet or the
	 * manifest names no such chunk.
	 */
	std::optional<incoming_chunk> begin_chunk(data_id const&, std::uint64_t chunk_no);

	/// a held encrypted chunk
	std::optional<octet_vector> read_chunk(data_id const&, std::uint64_t chunk_no) const;

	/// a piece of a held encrypted chunk (for the upload); nullopt when the chunk is not
	/// held or the range is not inside it
	std::optional<octet_vector> read_chunk_piece(data_id const&, std::uint64_t chunk_no, std::uint64_t offset, std::size_t size) const;

private:
	std::shared_ptr<record_data_store_impl> impl_;
};

}
