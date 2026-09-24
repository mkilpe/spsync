#pragma once

#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/util/result.hpp>

#include <functional>
#include <optional>

namespace securepath::sync {

/// how a transfer queue paces itself: the uploads and the downloads of a storage alike
struct transfer_config {
	/// datas moving at the same time, the rest wait in the order they were queued
	std::size_t max_datas{2};

	/// pieces of one data on the way without an answer yet; with the piece size this is
	/// what a data has in memory and on its way at once, whatever its chunk size
	std::size_t window{16};

	/// octets of a chunk per packet: a chunk travels in pieces (at most the protocol's
	/// max_data_piece_size)
	std::uint32_t piece_size{128 * 1024};
};

/// the transfer of a data ended: complete at the other end, or with the error that stopped it
using transfer_done_callback = std::function<void(data_id const&, std::optional<error>)>;

/// encrypted octets moved so far, of the data's enc_size
using transfer_progress_callback = std::function<void(data_id const&, std::uint64_t transferred, std::uint64_t total)>;

}
