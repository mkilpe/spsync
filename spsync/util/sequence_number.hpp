#ifndef SPSYNC_UTIL_SEQUENCE_NUMBER_HEADER
#define SPSYNC_UTIL_SEQUENCE_NUMBER_HEADER

#include <securepath/serialisation/types.hpp>
#include <securepath/serialisation/sequence.hpp>

#include <iosfwd>

namespace securepath::sync::util {

/**
 * Represents a sequence number, value 0 is not a valid sequence number.
 */
struct sequence_number {
	std::uint64_t value{};

	/// returns true if the sequence number is valid (!= 0)
	bool is_valid() const { return value != 0; }

	sequence_number& operator++();
	sequence_number operator++(int);

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & value;
	}
};

bool operator==(sequence_number const& left, sequence_number const& right);
bool operator!=(sequence_number const& left, sequence_number const& right);
bool operator<(sequence_number const& left, sequence_number const& right);

std::ostream& operator<<(std::ostream&, sequence_number const&);

}

#endif