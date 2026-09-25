// SPDX-License-Identifier: MIT

#include "sequence_number.hpp"

#include <ostream>

namespace securepath::sync::util {

sequence_number& sequence_number::operator++() {
	++value;
	return *this;
}

sequence_number sequence_number::operator++(int) {
	sequence_number s{*this};
	++value;
	return s;
}

sequence_number& sequence_number::operator--() {
	--value;
	return *this;
}

sequence_number sequence_number::operator--(int) {
	sequence_number s{*this};
	--value;
	return s;
}

sequence_number& sequence_number::operator+=(int v) {
	value += v;
	return *this;
}

sequence_number& sequence_number::operator-=(int v) {
	value -= v;
	return *this;
}

sequence_number operator+(sequence_number const& seq, std::uint64_t v) {
	return sequence_number{seq.value + v};
}

sequence_number operator+(std::uint64_t v, sequence_number const& seq) {
	return sequence_number{seq.value + v};
}

sequence_number operator-(sequence_number const& seq, std::uint64_t v) {
	return sequence_number{seq.value - v};
}

sequence_number operator-(std::uint64_t v, sequence_number const& seq) {
	return sequence_number{v - seq.value};
}

std::string to_string(sequence_number const& seq) {
	return seq.is_valid() ? std::to_string(seq.value) : "<invalid sequence number>";
}

std::ostream& operator<<(std::ostream& out, sequence_number const& seq) {
	out << to_string(seq);
	return out;
}

}
