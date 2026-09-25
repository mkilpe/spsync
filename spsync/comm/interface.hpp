// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"

#include <spsync/core/records/equivocation_proof.hpp>
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

	/**
	 * Downloads a data a stored record names from the storage's data servers into the
	 * data store (RD7). Answered with on_data_downloaded: no error when the data is
	 * complete here, data_not_held when the holders have only a part yet (the chunks they
	 * had are kept). Asking again for a data on its way returns the running download's
	 * handle; a lost connection ends it without an answer, what was received stays.
	 */
	virtual request_handle fetch_data(data_id const&) = 0;

	/// Tries to commit to a record
	virtual request_handle commit_record(record_handle) = 0;

	/**
	 * Uploads a data of the data store to the storage's data servers (RD7), to be asked
	 * once a record naming the data is server confirmed. Answered with on_data_uploaded;
	 * asking again for a data already on its way returns the handle of the running
	 * upload. A lost connection ends the upload without an answer, the chunks the server
	 * got stay there: ask again after the reconnect.
	 */
	virtual request_handle upload_data(data_id const&) = 0;

	/// Accessors to common, shared infrastructure
	virtual sync::progress& progress() const = 0;
	virtual record_storage& records() const = 0;

	/// the storage's record data store; null when the storage keeps no record data
	virtual record_data_store* data() const = 0;
};

/**
 * The interface which communication layer uses to notify about incoming changes
 */
struct comm_output : event_system::event_handler {

	comm_output(event_system::event_loop&);

	virtual ~comm_output() = default;

	/// called when connection to server established
	virtual void on_connected() = 0;

	/// called when disconnected from server
	virtual void on_disconnected(std::optional<error>) = 0;

	/// called as a response to fetch_sequence_number, newest sequence number on server
	/// together with the server identity (plan 4.5)
	virtual void on_sequence_number_response(request_handle, result<sequence_info> const&) = 0;

	/// called when record is received as a response to fetch_records call
	virtual void on_record_response(request_handle, record_response const&) = 0;

	/// called when a fetch_data ended: the data is complete in the data store, or the error
	virtual void on_data_downloaded(request_handle, std::optional<error>) = 0;

	/// called when the server tells that a data server holds a data of the storage
	/// (notify_data): a data that was remote_not_complete may be fetched now
	virtual void on_data_available(data_id, bool complete) {}

	/// called when the server shows proof that an origin server assigned one sequence of
	/// the storage to two records (plan 5.4); the storage id is what verifying it takes
	virtual void on_equivocation(storage_id const&, equivocation_proof const&) {}

	/// called when getting response to a commit attempt from the server
	virtual void on_commit_response(request_handle, commit_response const&) = 0;

	/// called when all data for a record has been uploaded or error occurred
	virtual void on_data_uploaded(request_handle, std::optional<error>) = 0;

	/// called when new record is received from the server, with the server signed
	/// assignment when one was sent
	virtual void on_record_received(chain_block const&, std::optional<block_envelope> const& = {}) = 0;

	/// this converts events to above virtual calls
	void handle_event(std::unique_ptr<event_system::event_base> ev) override;
};

/// Events that map to the comm_output virtual functions
namespace comm_events {
struct on_connected {
	typedef void type();
};
struct on_disconnected {
	typedef void type(std::optional<error>);
};
struct on_sequence_number_response {
	typedef void type(request_handle, result<sequence_info> const&);
};
struct on_record_response {
	typedef void type(request_handle, record_response const&);
};
struct on_data_downloaded {
	typedef void type(request_handle, std::optional<error>);
};
struct on_equivocation {
	typedef void type(storage_id, equivocation_proof);
};
struct on_data_available {
	typedef void type(data_id, bool);
};
struct on_commit_response {
	typedef void type(request_handle, commit_response const&);
};
struct on_data_uploaded {
	typedef void type(request_handle, std::optional<error>);
};
struct on_record_received {
	typedef void type(chain_block const&, std::optional<block_envelope> const&);
};
}
}

