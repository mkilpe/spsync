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

bool operator==(sequence_number const& left, sequence_number const& right) {
	return left.value == right.value;
}

bool operator!=(sequence_number const& left, sequence_number const& right) {
	return !(left == right);
}

bool operator<(sequence_number const& left, sequence_number const& right) {
	return left.value < right.value;
}

std::ostream& operator<<(std::ostream& out, sequence_number const& seq) {
	if(seq.is_valid()) {
		out << seq.value;
	} else {
		out << "<invalid sequence number>";
	}
	return out;
}

}
