#ifndef SPSYNC_COMM_INTERFACE_HEADER
#define SPSYNC_COMM_INTERFACE_HEADER

#include <spsync/core/record_interface.hpp>
#include <spsync/util/result.hpp>

#include <cstdint>

namespace securepath::sync {

class progress;
class record_storage;
class serialised_record;
class commit_response;

using util::sequence_number;
using util::result;

/// arbitrary number that associates comm_input request to comm_output response
using request_handle = std::uint32_t;

/**
 * The interface to push information to the server, eg. try to commit a record.
 * These calls will not block, but the responses comes via the comm_output interface.
 */
struct comm_input {
	virtual ~comm_input() = default;

	/// Fetches newest known sequence number from the server
	virtual request_handle fetch_sequence_number() = 0;

	/// Fetches records for specific range of sequence numbers [start, end]
	virtual request_handle fetch_records(sequence_number start, sequence_number end) = 0;

	/// Fetches record data for given record
	virtual request_handle fetch_data(sequence_number record) = 0;

	/// Tries to commit to a record and uploads the record data if committing was successful
	virtual request_handle commit_record(record_handle) = 0;

	/// Accessors to common, shared infrastructure
	virtual sync::progress& progress() const = 0;
	virtual record_storage& records() const = 0;
};

/**
 * The interface which communication layer uses to notify about incoming changes
 */
struct comm_output {
	virtual ~comm_output() = default;

	/// called as a response to fetch_sequence_number, newest sequence number on server
	virtual void on_sequence_number_response(request_handle, result<sequence_number> const&) = 0;

	/// called when record is received as a response to fetch_records call
	virtual void on_record_response(request_handle, result<std::deque<chain_block>> const&) = 0;

	/// called when record data is fully received as a response to fetch_data call
	virtual void on_data_response(request_handle, result<record_data_handle> const&) = 0;

	/// called when getting response to a commit attempt from the server
	virtual void on_commit_response(request_handle, result<chain_block> const&) = 0;

	/// called when all data for a record has been uploaded or error occurred
	virtual void on_data_uploaded(request_handle, std::optional<error>) = 0;

	/// called when new record is received from the server
	virtual void on_record_received(chain_block const&) = 0;

};

}

#endif