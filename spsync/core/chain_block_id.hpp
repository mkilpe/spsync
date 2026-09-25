// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/types.hpp>
#include <spsync/util/format.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::sync {

/// chain_block_id identifies a chain block by its sequence number and hash
struct chain_block_id {
	/// sequence number of a chain block
	sequence_number sequence;

	/// hash of the chain block
	octet_vector hash;

	/// true if has sequence number and hash
	bool is_valid() const {
		return sequence && !hash.empty();
	}

	bool operator==(chain_block_id const&) const = default;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & sequence & hash;
	}
};

inline std::string to_string(chain_block_id const& b) {
	// note: no closing paren, kept as the historical log format
	return std::format("({}, {}", b.sequence, to_hex(b.hash));
}

inline std::ostream& operator<<(std::ostream& out, chain_block_id const& b) {
	return out << to_string(b);
}

}


SPSYNC_FORMAT_VIA_TO_STRING(securepath::sync::chain_block_id)

