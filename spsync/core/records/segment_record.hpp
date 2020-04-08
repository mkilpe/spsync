#ifndef SPSYNC_CORE_SEGMENT_RECORD_HEADER
#define SPSYNC_CORE_SEGMENT_RECORD_HEADER

#include "record_base.hpp"
#include "encrypted_record_header.hpp"
#include "../segment_header.hpp"

#include <deque>

namespace securepath::sync {

/// The plain segment record data with non-encrypted data
class plain_segment_data {
public:

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & segment_start_ & segment_end_ & tags_ & trailing_data_;
	}

private:
	// Start and end of the segment in sequence numbers.
	// End sequence should be the same as the sequence of this record for now
	sequence_number segment_start_;
	sequence_number segment_end_;

	// Tags of the records in this segment in sequence number order starting from the smallest [segment_start, segment_end_)
	std::deque<record_tag> tags_;
	serialisation::trailing_data trailing_data_;
};

/// Segment record with encrypted header
class segment_record : public record_base {
public:
	segment_record() = default;
	segment_record(record_base base, plain_segment_data data, encrypted_record_header<segment_header> header)
	: record_base(std::move(base))
	, data_(std::move(data))
	, header_(std::move(header))
	{}

	/// Returns the user change data for this record
	plain_segment_data data() const { return data_; }

	/// Returns the encrypted header
	encrypted_record_header<segment_header> header() const { return header_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & static_cast<record_base&>(*this) & data_ & header_;
	}

private:
	plain_segment_data data_;
	encrypted_record_header<segment_header> header_;
};

}

#endif
