#pragma once

#include <spsync/core/sync_mode.hpp>
#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/core/data/data_ticket.hpp>
#include <spsync/core/record_interface.hpp>
#include <spsync/core/records/block_envelope.hpp>
#include <spsync/util/result.hpp>

#include <securepath/crypto/public_key_id.hpp>

#include <cstdint>
#include <vector>

namespace securepath::sync {

class progress;
class record_data_store;
class record_storage;
class serialised_record;

using util::sequence_number;
using util::result;

/// arbitrary number that associates comm_input request to comm_output response
using request_handle = std::uint32_t;

/// the sequence number answer together with the identity of the answering server (plan 4.5)
struct sequence_info {
	sequence_number sequence;
	/// signing key id of the server; invalid when the server states no identity
	crypto::public_key_id server_id;
	/// the storage's validity limits (0 = unknown, e.g. an old server)
	storage_limits limits;
	/// the data-role servers of the storage (record_data.txt RD12); empty when it carries no record data
	std::vector<data_endpoint> data_endpoints;
};

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

