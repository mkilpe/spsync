// SPDX-License-Identifier: MIT

#include "have_bitmap.hpp"

#include <algorithm>
#include <bit>

namespace securepath::sync {

have_bitmap::have_bitmap(std::uint64_t chunk_count)
: bits_((chunk_count + 7) / 8)
, chunk_count_(chunk_count)
{
}

have_bitmap::have_bitmap(std::uint64_t chunk_count, octet_vector bits)
: bits_(std::move(bits))
, chunk_count_(chunk_count)
{
	normalise();
}

void have_bitmap::normalise() {
	bits_.resize((chunk_count_ + 7) / 8);
	unsigned const used = static_cast<unsigned>(chunk_count_ % 8);
	if(used != 0) {
		bits_.back() &= static_cast<std::uint8_t>((1u << used) - 1u);
	}
}

bool have_bitmap::test(std::uint64_t chunk_no) const {
	return chunk_no < chunk_count_ && (bits_[chunk_no / 8] & (1u << (chunk_no % 8))) != 0;
}

void have_bitmap::set(std::uint64_t chunk_no, bool held) {
	if(chunk_no < chunk_count_) {
		auto const bit = static_cast<std::uint8_t>(1u << (chunk_no % 8));
		if(held) {
			bits_[chunk_no / 8] |= bit;
		} else {
			bits_[chunk_no / 8] &= static_cast<std::uint8_t>(~bit);
		}
	}
}

void have_bitmap::set_all() {
	for(auto& octet : bits_) {
		octet = 0xff;
	}
	normalise();
}

void have_bitmap::clear() {
	for(auto& octet : bits_) {
		octet = 0;
	}
}

std::uint64_t have_bitmap::count() const {
	std::uint64_t ret = 0;
	for(auto octet : bits_) {
		ret += static_cast<std::uint64_t>(std::popcount(octet));
	}
	return ret;
}

std::uint64_t have_bitmap::first_missing(std::uint64_t from) const {
	std::uint64_t ret = std::min(from, chunk_count_);
	while(ret < chunk_count_ && test(ret)) {
		++ret;
	}
	return ret;
}

}
