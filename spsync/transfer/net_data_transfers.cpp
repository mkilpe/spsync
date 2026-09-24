#include "net_data_transfers.hpp"

#include <spsync/core/progress.hpp>
#include <spsync/protocol/error.hpp>

#include <cassert>

namespace securepath::sync {

net_data_transfers::net_data_transfers(network::context& context, record_data_store& store, sync::progress& progress
	, data_channel* channel, data_download_channel* download_channel)
: context_(context)
, store_(store)
, progress_(progress)
, channel_(channel)
, download_channel_(download_channel)
{}

net_data_transfers::~net_data_transfers()
{
	// the retries first, then the transfers, then the channel whose ticket source is the owner's
	upload_retry_.reset();
	download_retry_.reset();
	uploader_.reset();
	downloader_.reset();
	own_channel_.reset();
}

void net_data_transfers::attach(ticket_source tickets, done_callback upload_done, done_callback download_done) {
	assert(!uploader_);
	upload_done_ = std::move(upload_done);
	download_done_ = std::move(download_done);
	if(!channel_ || !download_channel_) {
		own_channel_ = std::make_unique<net_data_channel>(context_, std::move(tickets));
		channel_ = channel_ ? channel_ : own_channel_.get();
		download_channel_ = download_channel_ ? download_channel_ : own_channel_.get();
	}
	make_queues(context_.io_context());
}

void net_data_transfers::make_queues(asio::io_context& io) {
	// the transfers run their rounds on the io context, not on whoever queued a data
	uploader_ = std::make_unique<data_uploader>(store_, *channel_, data_upload_config{}
		, [this](data_id const& id, std::optional<error> err) { on_upload_done(id, std::move(err)); }
		, [this](data_id const& id, std::uint64_t transferred, std::uint64_t total) {
			progress_.emit<progress_events::on_data_progress>(id, transferred, total, true);
		}, &io);
	downloader_ = std::make_unique<data_downloader>(store_, *download_channel_, data_download_config{}
		, [this](data_id const& id, std::optional<error> err) { on_download_done(id, std::move(err)); }
		, [this](data_id const& id, std::uint64_t transferred, std::uint64_t total) {
			progress_.emit<progress_events::on_data_progress>(id, transferred, total, false);
		}, &io);
	upload_retry_ = std::make_unique<transfer_retry>(io, transfer_retry_config{}, [this](data_id const& id) { uploader_->enqueue(id); });
	download_retry_ = std::make_unique<transfer_retry>(io, transfer_retry_config{}, [this](data_id const& id) { downloader_->enqueue(id); });
}

void net_data_transfers::upload(data_id const& id) {
	assert(uploader_);
	uploader_->enqueue(id);
}

void net_data_transfers::fetch(data_id const& id) {
	assert(downloader_);
	downloader_->enqueue(id);
}

void net_data_transfers::on_connected() {
	std::unique_lock lock{mutex_};
	connected_ = true;
}

void net_data_transfers::on_disconnected() {
	{
		std::unique_lock lock{mutex_};
		connected_ = false;
	}
	if(uploader_) {
		// what the server got stays there, what arrived here too; the owner asks again
		// after the reconnect
		upload_retry_->cancel();
		download_retry_->cancel();
		uploader_->reset();
		downloader_->reset();
	}
	if(own_channel_) {
		// tickets come over the record connection: without it the data connections have
		// nothing to do, and a client that went away takes them along anyway
		own_channel_->close();
	}
}

/**
 * A transfer that ended with an error another try may lift is tried again after a wait
 * (a lost data connection, a transfer quota window...): the owner hears of it when it
 * ends for good. Whatever wait was running for the data is over.
 */
bool net_data_transfers::retried(transfer_retry* retry, data_id const& id, std::optional<error> const& err) {
	bool connected{};
	{
		std::unique_lock lock{mutex_};
		connected = connected_;
	}
	// no retry object while this is going: a done that came during the teardown is reported
	bool const again = connected && retry && err && retryable_transfer_error(*err);
	if(again) {
		retry->schedule(id, protocol::retry_after(*err));
	} else if(retry) {
		retry->forget(id);
	}
	return again;
}

void net_data_transfers::on_upload_done(data_id const& id, std::optional<error> err) {
	if(!retried(upload_retry_.get(), id, err)) {
		upload_done_(id, std::move(err));
	}
}

void net_data_transfers::on_download_done(data_id const& id, std::optional<error> err) {
	if(!retried(download_retry_.get(), id, err)) {
		download_done_(id, std::move(err));
	}
}

}
