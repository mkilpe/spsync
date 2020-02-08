#ifndef SPSYNC_CORE_CHAIN_BLOCK_ID_HEADER
#define SPSYNC_CORE_CHAIN_BLOCK_ID_HEADER

#include <spsync/core/types.hpp>
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

inline std::ostream& operator<<(std::ostream& out, chain_block_id const& b) {
	return out << "(" << b.sequence << ", " << to_hex(b.hash);
}

}

#endif