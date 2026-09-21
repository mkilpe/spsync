#pragma once

#include "transfer_budget.hpp"

#include <spsync/core/data/record_data_store.hpp>
#include <spsync/util/result.hpp>

#include <filesystem>
#include <mutex>

namespace securepath::sync {

/**
 * Resource quota of a data server (record_data.txt RD10): server-local, it never makes a
 * record invalid - a refused upload degrades availability, another holder or a later try
 * may take the data. 0 = no limit.
 */
struct data_quota {
	/// the biggest single data (enc_size) this server takes
	std::uint64_t max_data_size{};

	/// what the data of one storage may take in total; an upload reserves its whole
	/// enc_size when it is opened, so uploads in progress cannot overshoot together
	std::uint64_t max_storage_bytes{};
};

/**
 * The data of one storage on a data-role server (RD5): the same chunk files and data
 * table as a client keeps (record_data_store), ciphertext only and verified against the
 * manifest, plus what only a server needs - the quota and the expiry of uploads that
 * never completed. The server never decrypts (D1) and knows no chain: what a data is and
 * that it belongs here is stated by the ticket the caller verified.
 *
 * Thread safe.
 */
/// what a download is opened with: the manifest to verify against and the chunks held here
struct served_data {
	data_manifest manifest;
	have_bitmap have;
};

class server_data_store {
public:
	server_data_store(database::connection_ptr, std::filesystem::path data_root, data_quota = {}, transfer_quota = {});

	/**
	 * Open the upload of a data or resume it: the chunks already held. Errors (protocol
	 * errc): data_too_big, invalid_data_manifest (not the descriptor's manifest, or the
	 * descriptor contradicts the known data), data_quota_exceeded.
	 */
	util::result<have_bitmap> open_upload(data_descriptor const&, data_manifest const&, time_point now);

	/**
	 * Keep a chunk of an opened upload; true when it completed the data. Errors:
	 * no_such_upload (no manifest for the data), invalid_data_chunk (not the chunk the
	 * manifest names there).
	 */
	util::result<bool> store_chunk(data_id const&, std::uint64_t chunk_no, octet_span encrypted, time_point now);

	/**
	 * The same for a chunk that arrives in pieces: begin, append the pieces to what
	 * begin_chunk gave, finish. Errors of begin: no_such_upload, invalid_data_chunk (the
	 * manifest names no such chunk); of finish: invalid_data_chunk (incomplete, or not
	 * the manifest's chunk - nothing of it is kept).
	 */
	util::result<incoming_chunk> begin_chunk(data_id const&, std::uint64_t chunk_no, time_point now);
	util::result<bool> finish_chunk(data_id const&, incoming_chunk&, time_point now);

	// -- serving (RD4, RDS 6) --

	/**
	 * Open the download of a data: its manifest and what is held of it, which may be a
	 * part while the upload is in progress. Error: data_not_held (unknown here, or the
	 * descriptor is not the one this data was uploaded with).
	 */
	util::result<served_data> open_download(data_descriptor const&) const;

	/**
	 * A piece of a held chunk, counted against the transfer quota of the window. Errors:
	 * data_not_held (the chunk is not held, the range is not inside it or above a
	 * piece), data_transfer_quota_exceeded (see retry_after).
	 */
	util::result<octet_vector> serve_piece(data_id const&, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size, time_point now);

	/// seconds until the transfer quota window of the time ends
	std::uint32_t retry_after(time_point now) const { return budget_.retry_after(now); }

	/// what is known of the data; in_sync = complete
	std::optional<data_state_row> find(data_id const&) const;

	/// a held encrypted chunk
	std::optional<octet_vector> read_chunk(data_id const&, std::uint64_t chunk_no) const;

	/// what the storage's data takes against the quota: the enc_size of every known data
	std::uint64_t used_bytes() const;

	/// every data held completely
	std::vector<data_state_row> complete_data() const;

	/// uploads that were opened and have not completed or expired
	std::uint64_t uploads_in_progress() const;

	/**
	 * Drop the incomplete uploads nothing touched since the given time, rows and chunks:
	 * their reservation is free again. Returns how many went.
	 */
	std::size_t expire_incomplete(time_point untouched_since);

private:
	util::result<bool> chunk_kept(data_id const&, time_point now);
	void touch(data_id const&, time_point now);
	void forget_activity(data_id const&);

private:
	mutable std::mutex mutex_;
	database::connection_ptr db_;
	record_data_store store_;
	data_state_table table_;
	data_quota const quota_;
	transfer_budget budget_;
};

}
