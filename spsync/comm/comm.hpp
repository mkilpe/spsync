#ifndef SPSYNC_COMM_COMM_HEADER
#define SPSYNC_COMM_COMM_HEADER

#include "interface.hpp"
#include <spsync/protocol/server_protocol.hpp>

#include <memory>

namespace securepath::sync {

using storage_id = octet_vector;
class network_connection_impl;

/**
 * The default implementation of the comm_input interface to talk with the server
 * This is not used directly but rather by network_connection
 */
class comm : public comm_input {
public:
	comm(network_connection_impl* nc_impl, storage_id, record_storage&, sync::progress&);
	~comm();

	/// set the handler for incoming event from network
	void set_output(event_system::event_handler&);

	/// called when virtual storage connection is connected
	void on_connected();

	/// called when virtual storage connection is disconnected
	void on_disconnected(error const& err);

	/// The incoming packet handling functions
	void handle(protocol::response_sequence_number const& p);
	void handle(protocol::response_records const& p);
	void handle(protocol::response_commit const& p);
	void handle(protocol::response_data const& p);
	void handle(protocol::notify_record const& p);

protected:

	// -- comm_input interface, see interface.hpp --
	virtual request_handle fetch_sequence_number() override;
	virtual request_handle fetch_records(sequence_number start, sequence_number end) override;
	virtual request_handle fetch_data(sequence_number record) override;
	virtual request_handle commit_record(record_handle) override;
	virtual sync::progress& progress() const override;
	virtual record_storage& records() const override;

private:
	network_connection_impl* const nc_impl_{};
	storage_id const sid_;
	record_storage& storage_;
	sync::progress& progress_;
	event_system::event_handler* output_{};
};

}

#endif