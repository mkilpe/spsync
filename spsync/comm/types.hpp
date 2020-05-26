#ifndef SPSYNC_COMM_TYPES_HEADER
#define SPSYNC_COMM_TYPES_HEADER

#include <spsync/core/record_interface.hpp>
#include <spsync/util/result.hpp>

#include <cstdint>

namespace securepath::sync {

class progress;
class record_storage;
class serialised_record;

using util::sequence_number;
using util::result;

/// arbitrary number that associates comm_input request to comm_output response
using request_handle = std::uint32_t;

struct record_response {
	sequence_number requested_max;
	sequence_number server_max_sequence;
	result<std::deque<chain_block>> data;
};

struct commit_response {
	/// this always contains the current sequence on the server if available (even if _data_ has an error)
	sequence_number server_max_sequence;
	/// result of the commit request
	result<chain_block> data;
};

}

#endif