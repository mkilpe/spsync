#pragma once

#include <spsync/core/record_interface.hpp>
#include <spsync/core/records/block_envelope.hpp>
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
	/// the biggest sequence that was returned
	sequence_number requested_max;
	/// the biggest sequence on the server, this combined with the previous one can be used to query records in chunks
	sequence_number server_max_sequence;
	/// returned chain blocks, notice that the server will return some maximum amount of records at once
	result<std::deque<chain_block>> data;
};

struct commit_response {
	/// this always contains the current sequence on the server if available (even if _data_ has an error)
	sequence_number server_max_sequence;
	/// result of the commit request
	result<chain_block> data;
	/// the server signed sequence assignment for the committed record
	std::optional<block_envelope> envelope;
};

}

