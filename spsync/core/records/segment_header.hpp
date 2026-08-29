#pragma once

#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * This is the encrypted header in the segment_record to seal a segment of records before it
 *
 */
class segment_header {
public:

	// time when this segment was created
	time_point creation_time;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & creation_time & metadata_ & trailing_data_;
	}
private:

	// arbitrary metadata for higher layers
	util::metadata metadata_;
	serialisation::trailing_data trailing_data_;
};

}

