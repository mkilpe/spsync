// SPDX-License-Identifier: MIT

#pragma once

#include <bit>
#include <cstdint>

namespace securepath::sync {

/// smallest padded size of record data (RD11): anything shorter looks like 4 KiB
std::uint64_t constexpr min_padded_data_size = 4096;

/// smallest padded size of an encrypted record header (RD11): short messages all look alike
std::uint64_t constexpr min_padded_header_size = 256;

/**
 * Size-class padding (RD11, Padme): the padded length keeps only the top
 * log2(size) - log2(log2(size)) bits of size, so an observer learns a size class, not
 * the length. The overhead is at most ~12% for small sizes and shrinks with size; sizes
 * up to floor all pad to floor.
 */
[[nodiscard]] constexpr std::uint64_t padded_size(std::uint64_t size, std::uint64_t floor) {
	std::uint64_t ret = floor;
	if(size > floor) {
		unsigned const e = 63u - static_cast<unsigned>(std::countl_zero(size));      // floor(log2 size)
		unsigned const s = 32u - static_cast<unsigned>(std::countl_zero(e));         // floor(log2 e) + 1
		unsigned const last_bits = e - s;
		std::uint64_t const mask = (std::uint64_t{1} << last_bits) - 1;
		ret = (size + mask) & ~mask;
	}
	return ret;
}

}
