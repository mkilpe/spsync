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

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & sequence & hash;
	}
};

inline bool operator==(chain_block_id const& l, chain_block_id const& r) {
	return l.sequence == r.sequence && l.hash ==  r.hash;
}

inline bool operator!=(chain_block_id const& l, chain_block_id const& r) {
	return !(l == r);
}

inline std::ostream& operator<<(std::ostream& out, chain_block_id const& b) {
	return out << "(" << b.sequence << ", " << to_hex(b.hash);
}

}


SPSYNC_FORMAT_VIA_OSTREAM(securepath::sync::chain_block_id)

