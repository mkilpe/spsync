// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * Which chunks of a data are held (RD5/RD6): one bit per chunk, chunk 0 is the lowest
 * bit of the first octet. The octets are what the data table persists and what a
 * transfer peer is told, so the unused bits of the last octet are always zero.
 */
class have_bitmap {
public:
	have_bitmap() = default;

	/// nothing held of a data with the given number of chunks
	explicit have_bitmap(std::uint64_t chunk_count);

	/// from stored octets; a blob of another length or with stray bits is normalised
	have_bitmap(std::uint64_t chunk_count, octet_vector bits);

	/// number of chunks of the data
	std::uint64_t size() const { return chunk_count_; }

	/// true when the chunk is held; false for a chunk number past the end
	bool test(std::uint64_t chunk_no) const;

	/// mark the chunk held (or not); a chunk number past the end is ignored
	void set(std::uint64_t chunk_no, bool held = true);

	/// mark every chunk held
	void set_all();

	/// nothing held
	void clear();

	/// number of chunks held
	std::uint64_t count() const;

	/// true when every chunk is held (a data without chunks is complete)
	bool complete() const { return count() == chunk_count_; }

	/// first chunk not held at or after from; size() when there is none
	std::uint64_t first_missing(std::uint64_t from = 0) const;

	octet_vector const& octets() const { return bits_; }

	bool operator==(have_bitmap const&) const = default;

private:
	void normalise();

private:
	octet_vector bits_;
	std::uint64_t chunk_count_{};
};

}
