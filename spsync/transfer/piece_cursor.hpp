// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/data/data_descriptor.hpp>

#include <deque>
#include <optional>

namespace securepath::sync {

/// one piece of a chunk: what a packet moves
struct piece_range {
	bool operator==(piece_range const&) const = default;

public:
	std::uint64_t chunk_no{};
	std::uint64_t offset{};
	std::uint32_t size{};
};

/**
 * Where the transfer of a data is, piece by piece (RD4): the chunks still to move go in
 * the order they were added, each in pieces of at most a given size from offset 0, the
 * last chunk and the last piece of a chunk as short as the descriptor says. A value:
 * what the transfer machines do with a piece is theirs, this only says which is next.
 */
class piece_cursor {
public:
	piece_cursor() = default;
	explicit piece_cursor(data_descriptor descriptor);

	data_descriptor const& descriptor() const { return descriptor_; }

	/// a chunk to move, after the ones added before
	void add(std::uint64_t chunk_no);

	/// nothing is left to move (pieces already handed out may still be on their way)
	bool done() const;

	/// the chunk the next piece starts, when it starts one
	std::optional<std::uint64_t> starting_chunk() const;

	/// the next piece, of at most piece_size octets (at least one); the cursor moves
	/// past it. Nothing when done
	std::optional<piece_range> next(std::uint32_t piece_size);

private:
	data_descriptor descriptor_;
	std::deque<std::uint64_t> pending_;
	std::optional<std::uint64_t> current_;
	std::uint64_t offset_{};
};

}
