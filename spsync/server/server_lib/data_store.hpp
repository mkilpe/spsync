// SPDX-License-Identifier: MIT

#pragma once

#include "transfer_budget.hpp"

#include <spsync/core/data/record_data_store.hpp>
#include <spsync/core/sync_mode.hpp>
#include <spsync/util/result.hpp>

#include <atomic>
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

/// what a data server takes at all, whatever a record server signed or asked for: a
/// descriptor a bitmap and a manifest can be sized from, and chunks of at most the biggest size
[[nodiscard]] inline bool storable_descriptor(data_descriptor const& d) {
	return usable_data_descriptor(d) && d.chunk_size <= chunk_size_range.highest;
}

/// what a download is opened with: the manifest to verify against and the chunks held here
struct served_data {
	data_manifest manifest;
	have_bitmap have;
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
	 * A chunk of an opened upload arrives in pieces: begin, append the pieces to what
	 * begin_chunk gave, finish - true when it completed the data. Errors of begin:
	 * no_such_upload (no manifest for the data), invalid_data_chunk (the manifest names
	 * no such chunk, or the chunk is held already); of finish: invalid_data_chunk
	 * (incomplete, or not the manifest's chunk - nothing of it is kept).
	 */
	util::result<incoming_chunk> begin_chunk(data_id const&, std::uint64_t chunk_no, time_point now);
	util::result<bool> finish_chunk(data_id const&, incoming_chunk&, time_point now);

	// -- holding a copy (RD8/RD13 replication, RDS 10) --

	/**
	 * Make room for the copy of a data another data server holds: the data becomes known
	 * by its descriptor - the manifest comes with the pull - and reserves its size like
	 * an upload. What is held of it already comes back, all of it when the copy is
	 * complete. Errors: data_too_big, data_quota_exceeded, invalid_data_manifest (the
	 * descriptor contradicts the known data).
	 */
	util::result<have_bitmap> open_replica(data_descriptor const&, time_point now);

	/**
	 * The chunk store a pull writes into, with the verification of a client download
	 * (comm/data_downloader works on it). What keeps the expiry off a copy on its way is
	 * the record server asking for it again with every sweep (open_replica touches it);
	 * when the pull has ended, replica_pulled settles the bookkeeping: true when the data
	 * is complete now.
	 */
	record_data_store& chunks() { return store_; }
	bool replica_pulled(data_id const&, time_point now);

	// -- serving (RD4, RDS 6) --

	/**
	 * Open the download of a data: its manifest and what is held of it, which may be a
	 * part while the upload is in progress. Error: data_not_held (unknown here, or the
	 * descriptor is not the one this data was uploaded with).
	 */
	util::result<served_data> open_download(data_descriptor const&) const;

	/**
	 * A piece of a held chunk, counted against the transfer quota of the window unless it
	 * is for a data server's copy (that quota is about what members move). Errors:
	 * data_not_held (the chunk is not held, the range is not inside it or above a
	 * piece), data_transfer_quota_exceeded (see retry_after).
	 */
	util::result<octet_vector> serve_piece(data_id const&, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size, time_point now
		, bool charged = true);

	/// seconds until the transfer quota window of the time ends
	std::uint32_t retry_after(time_point now) const { return budget_.retry_after(now); }

	/// what is known of the data; in_sync = complete
	std::optional<data_state_row> find(data_id const&) const;

	/// what the storage's data takes against the quota: the enc_size of every known data.
	/// A counter, like uploads_in_progress: read from the tables when the store opens,
	/// kept up by what changes them - not added up per question (a data server announces
	/// both with every completed data)
	std::uint64_t used_bytes() const;

	/// every data held completely
	std::vector<data_state_row> complete_data() const;

	/// uploads that were opened and have not completed or expired
	std::uint64_t uploads_in_progress() const;

	/**
	 * Drop the given data, rows and chunks (RD9): a record server said no record names
	 * them any more. Their reservation is free again. Returns how many were known here.
	 */
	std::size_t release(std::vector<data_id> const&);

	/**
	 * Drop the incomplete uploads nothing touched since the given time, rows and chunks:
	 * their reservation is free again. Returns how many went.
	 */
	std::size_t expire_incomplete(time_point untouched_since);

private:
	/// the quota and the registration shared by an upload and a copy; null manifest = not known yet
	util::result<have_bitmap> open(data_descriptor const&, data_manifest const* manifest, time_point now);
	/// a chunk was kept or a pull ended: true when the data is complete now
	bool chunk_kept(data_id const&, time_point now);
	void touch(data_id const&, time_point now);
	void forget_activity(data_id const&);
	bool has_activity(data_id const&) const;
	/// drop the data (rows and chunks), their sizes off the counter; returns how many were known
	std::size_t drop(std::vector<data_id> const&);

private:
	mutable std::mutex mutex_;
	database::connection_ptr db_;
	record_data_store store_;
	data_state_table table_;
	data_quota const quota_;
	transfer_budget budget_;
	/// see used_bytes(); atomic so that the load signals need no lock
	std::atomic<std::uint64_t> used_bytes_{0};
	std::atomic<std::uint64_t> uploads_in_progress_{0};
};

}
