#pragma once

#include "data_channel.hpp"
#include "data_downloader.hpp"
#include "data_uploader.hpp"
#include "net_data_channel.hpp"
#include "transfer_retry.hpp"

#include <spsync/core/data/data_transfers.hpp>

#include <memory>
#include <mutex>

namespace securepath::sync {

class progress;
class record_data_store;

/**
 * The data transfers of a storage connection over the network: an uploader and a
 * downloader over the storage's data servers (net_data_channel, with the tickets the
 * record connection provides), progress on the progress handler, and another try for
 * a transfer that ended with an error a later try may lift (RDS 7) - as long as the
 * record connection is up; without it the owner queues the data again after the
 * reconnect, a retry would only ask for a ticket nobody answers. The channels can be
 * given (tests); without them the real one is made at attach.
 */
class net_data_transfers : public data_transfers {
public:
	net_data_transfers(network::context&, record_data_store&, sync::progress&
		, data_channel* channel = nullptr, data_download_channel* download_channel = nullptr);
	~net_data_transfers();

	void attach(ticket_source, done_callback upload_done, done_callback download_done) override;
	void upload(data_id const&) override;
	void fetch(data_id const&) override;
	void on_connected() override;
	void on_disconnected() override;

private:
	void make_queues(asio::io_context&);
	void on_upload_done(data_id const&, std::optional<error>);
	void on_download_done(data_id const&, std::optional<error>);
	/// true when the ended transfer is tried again by itself: nothing is reported yet
	bool retried(transfer_retry*, data_id const&, std::optional<error> const&);

private:
	network::context& context_;
	record_data_store& store_;
	sync::progress& progress_;
	data_channel* channel_{};
	data_download_channel* download_channel_{};
	std::mutex mutex_;
	/// the record connection is up: a transfer that ended may be tried again. Without it
	/// a done that came late or a retry that fired late does nothing
	bool connected_{};
	done_callback upload_done_;
	done_callback download_done_;
	/// the real data channel, made at attach when none was given
	std::unique_ptr<net_data_channel> own_channel_;
	/// declared after the channel they use
	std::unique_ptr<data_uploader> uploader_;
	std::unique_ptr<data_downloader> downloader_;
	/// declared last, so they go first
	std::unique_ptr<transfer_retry> upload_retry_;
	std::unique_ptr<transfer_retry> download_retry_;
};

}
