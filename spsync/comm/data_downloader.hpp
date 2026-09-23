#pragma once

#include "data_channel.hpp"
#include "transfer_config.hpp"

#include <spsync/core/data/record_data_store.hpp>

#include <functional>
#include <memory>
#include <optional>

namespace securepath::sync {

/// the pacing of the downloads (transfer_config.hpp)
using data_download_config = transfer_config;

/**
 * The download queue of a storage (RD4/RD7), the mirror of data_uploader: a data comes
 * down as its manifest - checked against the descriptor the record commits to - and then
 * the chunks that are missing here and held there, each in pieces appended to a staged
 * file and verified against the manifest when whole (record_data_store::begin_chunk).
 * What is received is kept chunk by chunk, so a download that ends early - the holder
 * has only a part yet, a transfer quota, a lost connection - goes on from there next time.
 *
 * A download ends with no error when the data is complete here, with data_not_held when
 * the holder lacked chunks (the upload is still in progress: remote_not_complete), else
 * with what stopped it. The store flips the data to in_sync itself with the last chunk.
 *
 * Thread safe; the channel and the callbacks are called without the lock (action_pump).
 */
class data_downloader {
public:
	using done_callback = transfer_done_callback;

	/// encrypted octets held here, of the data's enc_size
	using progress_callback = transfer_progress_callback;

	data_downloader(record_data_store&, data_download_channel&, data_download_config, done_callback, progress_callback = {});
	~data_downloader();

	/// queue a data a stored record names; false when it is already queued or on its way
	bool enqueue(data_id const&);

	/// the connection went: forget the queue and what is on the way (chunks half way are
	/// dropped, whole ones are kept); no callback is made for it
	void reset();

	std::size_t queued() const;
	std::size_t in_flight() const;

private:
	class impl;
	std::shared_ptr<impl> impl_;
};

}
