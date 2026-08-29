#pragma once

#include <securepath/serialisation/types.hpp>
#include <spsync/util/format.hpp>
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
	sequence_number& operator--();
	sequence_number operator--(int);
	sequence_number& operator+=(int);
	sequence_number& operator-=(int);
	explicit operator bool() const { return value; }

	bool operator==(sequence_number const&) const = default;
	auto operator<=>(sequence_number const&) const = default;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & value;
	}
};

sequence_number operator+(sequence_number const&, std::uint64_t);
sequence_number operator+(std::uint64_t, sequence_number const&);
sequence_number operator-(sequence_number const&, std::uint64_t);
sequence_number operator-(std::uint64_t, sequence_number const&);

std::ostream& operator<<(std::ostream&, sequence_number const&);

}


SPSYNC_FORMAT_VIA_OSTREAM(securepath::sync::util::sequence_number)

