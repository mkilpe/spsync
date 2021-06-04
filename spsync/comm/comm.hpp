#ifndef SPSYNC_COMM_COMM_HEADER
#define SPSYNC_COMM_COMM_HEADER

#include "interface.hpp"
#include <spsync/protocol/server_protocol.hpp>

#include <memory>

namespace securepath::sync {

/**
 * The default implementation of the comm_input interface to talk with the server
 */
class comm : public comm_input {
public:
	comm(record_storage&, sync::progress&);
	~comm();

	void set_output(event_system::event_handler&);

	void on_connected();
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
	record_storage& storage_;
	sync::progress& progress_;
	event_system::event_handler* output_{};
};

}

#endif