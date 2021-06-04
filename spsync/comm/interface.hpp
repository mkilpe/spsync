#ifndef SPSYNC_COMM_INTERFACE_HEADER
#define SPSYNC_COMM_INTERFACE_HEADER

#include "types.hpp"
#include <securepath/event_system/event_handler.hpp>
#include <securepath/event_system/event_loop.hpp>

namespace securepath::sync {

/**
 * The interface to push information to the server, eg. try to commit a record.
 * These calls will not block, but the responses comes via the comm_output interface.
 */
struct comm_input {
	virtual ~comm_input() = default;

	/// Fetches newest known sequence number from the server
	virtual request_handle fetch_sequence_number() = 0;

	/// Fetches records for specific range of sequence numbers [start, end]. If end is invalid, the server max sequence is used.
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
struct comm_output : event_system::event_handler {

	comm_output(event_system::event_loop_base&);

	virtual ~comm_output() = default;

	/// called when connection to server established
	virtual void on_connected() = 0;

	/// called when disconnected from server
	virtual void on_disconnected(std::optional<error>) = 0;

	/// called as a response to fetch_sequence_number, newest sequence number on server
	virtual void on_sequence_number_response(request_handle, result<sequence_number> const&) = 0;

	/// called when record is received as a response to fetch_records call
	virtual void on_record_response(request_handle, record_response const&) = 0;

	/// called when record data is fully received as a response to fetch_data call
	virtual void on_data_response(request_handle, result<record_data_handle> const&) = 0;

	/// called when getting response to a commit attempt from the server
	virtual void on_commit_response(request_handle, commit_response const&) = 0;

	/// called when all data for a record has been uploaded or error occurred
	virtual void on_data_uploaded(request_handle, std::optional<error>) = 0;

	/// called when new record is received from the server
	virtual void on_record_received(chain_block const&) = 0;

	// this converts events to above virtual calls
	void handle_event(std::unique_ptr<event_system::event_base> ev) override;
};

namespace comm_events {
struct on_connected {
	typedef void type();
};
struct on_disconnected {
	typedef void type(std::optional<error>);
};
struct on_sequence_number_response {
	typedef void type(request_handle, result<sequence_number> const&);
};
struct on_record_response {
	typedef void type(request_handle, record_response const&);
};
struct on_data_response {
	typedef void type(request_handle, result<record_data_handle> const&);
};
struct on_commit_response {
	typedef void type(request_handle, commit_response const&);
};
struct on_data_uploaded {
	typedef void type(request_handle, std::optional<error>);
};
struct on_record_received {
	typedef void type(chain_block const&);
};
}
}

#endif