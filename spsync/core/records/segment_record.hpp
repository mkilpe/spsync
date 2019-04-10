#ifndef SPSYNC_CORE_SEGMENT_RECORD_HEADER
#define SPSYNC_CORE_SEGMENT_RECORD_HEADER

#include "record_base.hpp"

namespace securepath::sync {

class segment_record : public record_base {
public:

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & segment_start_ & segment_end_ & tags_ & header_ & trailing_data_;
	}

private:
	// Start and end of the segment in sequence numbers.
	// End sequence should be the same as the sequence of this record for now
	sequence_number segment_start_;
	sequence_number segment_end_;

	// Tags of the records in this segment in sequence number oder starting from the smallest [segment_start, segment_end_)
	std::deque<octet_vector> tags_;

	encrypted_record_header<segment_header> header_;
	serialisation::trailing_data trailing_data_;
};

}

#endif
