#ifndef SPSYNC_UTIL_SEQUENCE_NUMBER_HEADER
#define SPSYNC_UTIL_SEQUENCE_NUMBER_HEADER

#include <securepath/serialisation/types.hpp>

namespace securepath::sync::util {

/**
 * Represents a sequence number, value 0 is not a valid sequence number.
 */
struct sequence_number {
	std::uint64_t value{};

	/// returns true if the sequence number is valid (!= 0)
	bool valid() const { return value != 0; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialiation::sequence<Ar> seq(ar);
		seq & value;
	}
};

}

#endif