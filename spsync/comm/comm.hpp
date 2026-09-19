#pragma once

#include "data_uploader.hpp"
#include "interface.hpp"
#include <spsync/core/sync_mode.hpp>
#include <spsync/protocol/server_protocol.hpp>

#include <map>
#include <memory>
#include <mutex>

namespace securepath::sync {

using storage_id = octet_vector;
class network_connection_impl;

/**
 * The default implementation of the comm_input interface to talk with the server
 * This is not used directly but rather by network_connection
 */
class comm : public comm_input {
public:
	/**
	 * data and channel are the storage's record data store and the way to its data
	 * servers; without both the storage uploads nothing (upload_data answers not_supported)
	 */
	comm(network_connection_impl* nc_impl, storage_id, record_storage&, sync::progress&, std::optional<storage_modes> expected_modes = {}
		, record_data_store* data = nullptr, data_channel* channel = nullptr);
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
	virtual request_handle upload_data(data_id const&) override;
	virtual sync::progress& progress() const override;
	virtual record_storage& records() const override;
	virtual record_data_store* data() const override;

private:
	void on_upload_done(data_id const&, std::optional<error>);

private:
	network_connection_impl* const nc_impl_{};
	storage_id const sid_;
	std::optional<storage_modes> const expected_modes_;
	record_storage& storage_;
	sync::progress& progress_;
	event_system::event_handler* output_{};

	record_data_store* const data_{};
	std::mutex upload_mutex_;
	/// the request handles of the uploads on their way
	std::map<data_id, request_handle> uploads_;
	/// set when the storage has a data store and a data channel
	std::unique_ptr<data_uploader> uploader_;
};

}

