#include "comm.hpp"
#include "net_connection_impl.hpp"

#include <spsync/core/progress.hpp>
#include <spsync/protocol/error.hpp>

namespace securepath::sync {

comm::comm(network_connection_impl* nc_impl, storage_id sid, record_storage& s, sync::progress& p, std::optional<storage_modes> expected_modes
	, record_data_store* data, data_channel* channel)
: nc_impl_(nc_impl)
, sid_(std::move(sid))
, expected_modes_(expected_modes)
, storage_(s)
, progress_(p)
, data_(data)
{
	if(data && channel) {
		uploader_ = std::make_unique<data_uploader>(*data, *channel, data_upload_config{}
			, [this](data_id const& id, std::optional<error> err) { on_upload_done(id, std::move(err)); }
			, [this](data_id const& id, std::uint64_t transferred, std::uint64_t total) {
				progress_.emit<progress_events::on_data_progress>(id, transferred, total, true);
			});
	}
}

comm::~comm()
{
}

void comm::set_output(event_system::event_handler& handler) {
	output_ = &handler;
}

void comm::on_connected() {
	assert(output_);
	output_->emit<comm_events::on_connected>();
}

void comm::on_disconnected(error const& err) {
	assert(output_);
	if(uploader_) {
		// what the server got stays there; the engine asks again after the reconnect
		uploader_->reset();
	}
	{
		std::unique_lock lock{upload_mutex_};
		uploads_.clear();
	}
	std::optional<error> opt_err;
	if(err) {
		opt_err = err;
	}
	output_->emit<comm_events::on_disconnected>(opt_err);
}

void comm::handle(protocol::response_sequence_number const& p) {
	assert(output_);
	result<sequence_info> arg;
	if(p.error) {
		arg = result<sequence_info>{protocol::to_error(p.error)};
	} else {
		// the server identity is the transport key: the pk handshake authenticated it,
		// so it needs no packet field (plan 4.5)
		arg = result<sequence_info>{sequence_info{p.sequence
			, nc_impl_->remote_key_id().value_or(crypto::public_key_id{})
			, storage_limits{p.max_record_size, p.chunk_size}}};
	}
	output_->emit<comm_events::on_sequence_number_response>(p.cid, std::move(arg));
	if(p.error && protocol::to_error(p.error).code() == make_error_code(protocol::errc::storage_syncing)) {
		// the replica is still catching up (plan 5.2): drop the session so the
		// connection owner reconnects, rotating to another replica when it has one
		LOG_INFO("replica is syncing the storage, closing the session to try another replica");
		nc_impl_->close(protocol::to_error(p.error));
	}
}

void comm::handle(protocol::response_records const& p) {
	LOG_TRACE("comm::handle(response_records)");
	assert(output_);
	record_response arg;
	if(p.error) {
		arg.data = result<std::deque<chain_block>>{protocol::to_error(p.error)};
	} else {
		arg.data = result<std::deque<chain_block>>{p.records};
	}
	arg.requested_max = p.requested_max;
	arg.server_max_sequence = p.server_max_sequence;

	output_->emit<comm_events::on_record_response>(p.cid, std::move(arg));
}

void comm::handle(protocol::response_commit const& p) {
	assert(output_);
	commit_response arg;
	if(p.error) {
		arg.data = result<chain_block>{protocol::to_error(p.error)};
	} else {
		if(p.record) {
			arg.data = result<chain_block>{*p.record};
		} else {
			arg.data = result<chain_block>{make_error(securepath::errc::unknown_error)};
		}
	}
	arg.server_max_sequence = p.server_max_sequence;
	arg.envelope = p.envelope;

	output_->emit<comm_events::on_commit_response>(p.cid, std::move(arg));
}

void comm::handle(protocol::response_data const& p) {
	assert(output_);
}

void comm::handle(protocol::notify_record const& p) {
	assert(output_);
	output_->emit<comm_events::on_record_received>(p.record, p.envelope);
}

request_handle comm::fetch_sequence_number() {
	return nc_impl_->fetch_sequence_number(sid_, expected_modes_);
}

request_handle comm::fetch_records(sequence_number start, sequence_number end) {
	return nc_impl_->fetch_records(sid_, start, end);
}

request_handle comm::fetch_data(sequence_number record) {
	assert(0);
	return request_handle{};
}

request_handle comm::commit_record(record_handle h) {
	return nc_impl_->commit_record(sid_, h->record());
}

request_handle comm::upload_data(data_id const& id) {
	assert(output_);
	request_handle handle{};
	bool is_new = false;
	{
		std::unique_lock lock{upload_mutex_};
		auto it = uploads_.find(id);
		is_new = it == uploads_.end();
		if(is_new) {
			it = uploads_.emplace(id, ++nc_impl_->call_id).first;
		}
		handle = it->second;
	}
	if(is_new) {
		if(uploader_) {
			uploader_->enqueue(id);
		} else {
			on_upload_done(id, make_error(securepath::errc::not_supported, "the storage has no data channel"));
		}
	}
	return handle;
}

void comm::on_upload_done(data_id const& id, std::optional<error> err) {
	std::optional<request_handle> handle;
	{
		std::unique_lock lock{upload_mutex_};
		auto it = uploads_.find(id);
		if(it != uploads_.end()) {
			handle = it->second;
			uploads_.erase(it);
		}
	}
	if(handle) {
		output_->emit<comm_events::on_data_uploaded>(*handle, std::move(err));
	}
}

sync::progress& comm::progress() const {
	return progress_;
}

record_storage& comm::records() const {
	return storage_;
}

record_data_store* comm::data() const {
	return data_;
}

}
