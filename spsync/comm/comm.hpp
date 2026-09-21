#pragma once

#include "data_downloader.hpp"
#include "data_uploader.hpp"
#include "interface.hpp"
#include "net_data_channel.hpp"
#include "transfer_retry.hpp"
#include <spsync/core/sync_mode.hpp>
#include <spsync/protocol/server_protocol.hpp>

#include <functional>
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
	 * data is the storage's record data store; without one the storage uploads nothing
	 * (upload_data answers not_supported). channel is the way to the storage's data
	 * servers: when none is given comm makes the real one (net_data_channel) with tickets
	 * asked from the record server over this connection (record_data.txt RD12).
	 */
	comm(network_connection_impl* nc_impl, storage_id, record_storage&, sync::progress&, std::optional<storage_modes> expected_modes = {}
		, record_data_store* data = nullptr, data_channel* channel = nullptr, data_download_channel* download_channel = nullptr);
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
	void handle(protocol::response_data_ticket const& p);
	void handle(protocol::notify_record const& p);
	void handle(protocol::notify_data const& p);

	/// asks the record server of this storage for data tickets; answers come through handle()
	ticket_source tickets();

protected:

	// -- comm_input interface, see interface.hpp --
	virtual request_handle fetch_sequence_number() override;
	virtual request_handle fetch_records(sequence_number start, sequence_number end) override;
	virtual request_handle fetch_data(data_id const&) override;
	virtual request_handle commit_record(record_handle) override;
	virtual request_handle upload_data(data_id const&) override;
	virtual sync::progress& progress() const override;
	virtual record_storage& records() const override;
	virtual record_data_store* data() const override;

private:
	/// a transfer direction: the handles of the datas on their way
	using transfers = std::map<data_id, request_handle>;

	request_handle start_transfer(transfers&, data_id const&, bool& is_new);
	std::optional<request_handle> end_transfer(transfers&, data_id const&);
	void on_upload_done(data_id const&, std::optional<error>);
	void on_download_done(data_id const&, std::optional<error>);
	/// true when the ended transfer is tried again by itself: nothing is reported yet
	bool retried(transfer_retry*, data_id const&, std::optional<error> const&);
	void fail_ticket_requests(error const&);

private:
	network_connection_impl* const nc_impl_{};
	storage_id const sid_;
	std::optional<storage_modes> const expected_modes_;
	record_storage& storage_;
	sync::progress& progress_;
	event_system::event_handler* output_{};

	record_data_store* const data_{};
	std::mutex upload_mutex_;
	/// the request handles of the uploads and downloads on their way
	transfers uploads_;
	transfers downloads_;
	/// ticket requests without an answer yet
	std::map<request_handle, std::move_only_function<void(util::result<data_grant>)>> ticket_requests_;
	/// the real data channel, made here when the storage has a data store and no channel was given
	std::unique_ptr<net_data_channel> own_channel_;
	/// set when the storage has a data store; declared after the channel they use
	std::unique_ptr<data_uploader> uploader_;
	std::unique_ptr<data_downloader> downloader_;
	/// tries ended transfers again without waiting for a reconnect (RDS 7); declared last,
	/// so they go first
	std::unique_ptr<transfer_retry> upload_retry_;
	std::unique_ptr<transfer_retry> download_retry_;
};

}

