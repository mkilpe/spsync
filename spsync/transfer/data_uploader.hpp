// SPDX-License-Identifier: MIT

#pragma once

#include "data_channel.hpp"
#include "transfer_config.hpp"

#include <spsync/core/data/record_data_store.hpp>

#include <asio/io_context.hpp>

#include <functional>
#include <memory>
#include <optional>

namespace securepath::sync {

/// the pacing of the uploads (transfer_config.hpp)
using data_upload_config = transfer_config;

/**
 * The upload queue of a storage (RD4/RD7): datas are uploaded in the order they were
 * queued - the commit order of their records - a few at a time, each as manifest first,
 * then the chunks the holder does not have yet. A chunk goes in pieces read straight
 * from its file, the pieces of a chunk in order, a window of pieces on the way at once,
 * so the memory an upload takes does not grow with the chunk size. Resuming an
 * interrupted upload is the same flow: the holder's answer to the manifest says which
 * chunks are left (a chunk that was on its way starts over).
 *
 * The uploader moves ciphertext from the data store to a data_channel and nothing else:
 * it does not touch the data's state, the owner does when told the data is done.
 *
 * Thread safe. The channel is never called with the uploader's lock held and may answer
 * from any thread, also before its call returns. The callbacks are called without the
 * lock, one at a time. The store IS called under the lock, from whatever thread answers
 * (a connection's strand): its calls are short, a chunk file is read piece by piece
 * outside it. What the two directions share is transfer_queue.
 */
class data_uploader {
public:
	/// the upload of a data ended: completely at the holder, or with the error that stopped it
	using done_callback = transfer_done_callback;

	/// encrypted octets known to be at the holder, of the data's enc_size
	using progress_callback = transfer_progress_callback;

	/// with an io context the transfers run on it (transfer_queue.hpp); without one on the caller
	data_uploader(record_data_store&, data_channel&, data_upload_config, done_callback, progress_callback = {}, asio::io_context* = nullptr);
	~data_uploader();

	/// queue a data; false when it is already queued or on its way
	bool enqueue(data_id const&);

	/**
	 * The connection went: forget the queue and what is on the way; the answers still
	 * coming for it are ignored. A done callback whose round was collected before the
	 * reset can still be made after it - the owner keeps its own idea of what is
	 * connected (comm does) and queues again after the reconnect.
	 */
	void reset();

	std::size_t queued() const;
	std::size_t in_flight() const;

private:
	class impl;
	std::shared_ptr<impl> impl_;
};

}
