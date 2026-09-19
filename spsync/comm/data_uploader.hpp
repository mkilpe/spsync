#pragma once

#include "data_channel.hpp"

#include <spsync/core/data/record_data_store.hpp>

#include <functional>
#include <memory>
#include <optional>

namespace securepath::sync {

struct data_upload_config {
	/// datas uploading at the same time, the rest wait in the order they were queued
	std::size_t max_datas{2};

	/// pieces of one data sent without an answer yet; with the piece size this is what a
	/// data has in memory and on its way at once, whatever its chunk size
	std::size_t window{16};

	/// octets of a chunk per packet: a chunk travels in pieces (at most the protocol's
	/// max_data_piece_size)
	std::uint32_t piece_size{128 * 1024};
};

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
 * lock, one at a time.
 */
class data_uploader {
public:
	/// the upload of a data ended: completely at the holder, or with the error that stopped it
	using done_callback = std::function<void(data_id const&, std::optional<error>)>;

	/// encrypted octets known to be at the holder, of the data's enc_size
	using progress_callback = std::function<void(data_id const&, std::uint64_t transferred, std::uint64_t total)>;

	data_uploader(record_data_store&, data_channel&, data_upload_config, done_callback, progress_callback = {});
	~data_uploader();

	/// queue a data; false when it is already queued or on its way
	bool enqueue(data_id const&);

	/**
	 * The connection went: forget the queue and what is on the way, answers still coming
	 * for it are ignored and no callback is made for it. The owner queues again after
	 * the reconnect.
	 */
	void reset();

	std::size_t queued() const;
	std::size_t in_flight() const;

private:
	class impl;
	std::shared_ptr<impl> impl_;
};

}
