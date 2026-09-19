#pragma once

#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/core/data/data_manifest.hpp>
#include <spsync/core/data/have_bitmap.hpp>
#include <spsync/util/result.hpp>

#include <functional>
#include <optional>

namespace securepath::sync {

/**
 * The way to the data servers of a storage as the transfer logic sees it (RD4/RD12).
 * What is behind it - the ticket from the record server, the choice of a holder, the
 * data connection - is the implementation's business; the transfer logic only moves a
 * manifest and the chunks, piece by piece.
 *
 * Every call is answered exactly once through its callback, from any thread and
 * possibly before the call returns. A lost connection answers the calls still out with
 * an error.
 */
struct data_channel {
	virtual ~data_channel() = default;

	using open_callback = std::move_only_function<void(util::result<have_bitmap>)>;
	using piece_callback = std::move_only_function<void(std::optional<error>)>;

	/**
	 * Open the upload of a data, or resume it: the holder checks the manifest against
	 * the committed descriptor and answers with the chunks it already has.
	 */
	virtual void open_upload(data_descriptor const&, data_manifest const&, open_callback) = 0;

	/**
	 * Send one piece of a chunk of an opened upload: bytes of the encrypted chunk from
	 * offset. A chunk never travels whole - the pieces of a chunk are sent in order from
	 * offset 0, the holder verifies the chunk against the manifest when its last piece
	 * is in and answers that piece with the verdict.
	 */
	virtual void send_piece(data_id const&, std::uint64_t chunk_no, std::uint64_t offset, octet_vector bytes, piece_callback) = 0;
};

}
