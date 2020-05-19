#ifndef SPSYNC_PROTOCOL_SERVER_PROTOCOL_HEADER
#define SPSYNC_PROTOCOL_SERVER_PROTOCOL_HEADER

#include "protocol_base.hpp"

namespace securepath::sync {

// called as a response to fetch_sequence_number, newest sequence number on server
//virtual void on_sequence_number_response(request_handle, result<sequence_number> const&) = 0;

// called when record is received as a response to fetch_records call
//virtual void on_record_response(request_handle, result<std::deque<chain_block>> const&) = 0;

// called when record data is fully received as a response to fetch_data call
//virtual void on_data_response(request_handle, result<record_data_handle> const&) = 0;

// called when getting response to a commit attempt from the server
//virtual void on_commit_response(request_handle, result<chain_block> const&) = 0;

// called when all data for a record has been uploaded or error occurred
//virtual void on_data_uploaded(request_handle, std::optional<error>) = 0;

// called when new record is received from the server
//virtual void on_record_received(chain_block const&) = 0;

}

#endif