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
 * Stream a whole source into a writer in pieces, never holding more than one piece
 * (RD7: "stream the source once"). Throws when the source ends before its size().
 */
void copy_record_data(record_data& source, data_writer& writer);

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

	void set_state(data_id const&, record_data_state);

	/**
	 * Drop the local chunks (state removed, refetchable), the row and the manifest stay.
	 * Refused (false) for an unknown data and while upload_pending: the chunks may be
	 * the only copy.
	 */
	bool evict(data_id const&);

	/**
	 * Drop the rows and chunks of every data the predicate does not know as referenced
	 * (RD9: data of rolled back or cut records, leftovers of a creation whose record
	 * never got stored). Returns how many went. The caller must not run this between a
	 * writer's finish() and the creation of its record.
	 */
	std::size_t remove_unreferenced(std::function<bool(std::uint64_t local_id)> const& is_referenced);

	// -- transfer side, ciphertext only --

	/// keep the manifest of a known data; false when it is not the one the descriptor commits to
	bool set_manifest(data_id const&, data_manifest const&);

	std::optional<data_manifest> manifest(data_id const&) const;

	/**
	 * Keep a received chunk: it must be the one the manifest names, so the manifest
	 * comes first. The last missing chunk flips the data to in_sync. False when the
	 * chunk does not verify.
	 */
	bool store_chunk(data_id const&, std::uint64_t chunk_no, octet_span encrypted);

	/// a held encrypted chunk (for the upload)
	std::optional<octet_vector> read_chunk(data_id const&, std::uint64_t chunk_no) const;

private:
	std::shared_ptr<record_data_store_impl> impl_;
};

}
