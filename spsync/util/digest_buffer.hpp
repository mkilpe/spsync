// SPDX-License-Identifier: MIT

#pragma once

#include <securepath/util/octet_vector.hpp>
#include <securepath/util/span.hpp>

#include <cstdint>
#include <string_view>

namespace securepath::sync::util {

/**
 * The octets a signature digest is taken over: a context string that separates the uses
 * of a key, then the signed fields as fixed width big endian integers and length
 * prefixed octet strings, so two different field sequences never give the same octets.
 */
/// append the lowest `octets` octets of v, big endian
inline void append_big_endian(octet_vector& out, std::uint64_t v, int octets) {
	for(int i = octets - 1; i >= 0; --i) {
		out.push_back(std::uint8_t(v >> (i * 8)));
	}
}

class digest_buffer {
public:
	explicit digest_buffer(std::string_view context)
	: octets_(context.begin(), context.end())
	{}

	digest_buffer& u32(std::uint32_t v) {
		append_big_endian(octets_, v, 4);
		return *this;
	}

	digest_buffer& u64(std::uint64_t v) {
		append_big_endian(octets_, v, 8);
		return *this;
	}

	/// length prefixed octets
	digest_buffer& sized(octet_span v) {
		u32(std::uint32_t(v.size()));
		octets_.insert(octets_.end(), v.begin(), v.end());
		return *this;
	}

	octet_vector const& octets() const { return octets_; }

private:
	octet_vector octets_;
};

}
