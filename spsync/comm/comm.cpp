#include "comm.hpp"
#include "net_connection_impl.hpp"

#include <spsync/core/progress.hpp>
#include <spsync/protocol/error.hpp>

namespace securepath::sync {

comm::comm(network_connection_impl* nc_impl, storage_id sid, record_storage& s, sync::progress& p, std::optional<storage_modes> expected_modes
	, record_data_store* data, std::unique_ptr<data_transfers> transfers)
: nc_impl_(nc_impl)
, sid_(std::move(sid))
, expected_modes_(expected_modes)
, storage_(s)
, progress_(p)
, data_(data)
, transfers_(std::move(transfers))
{
	assert(!transfers_ || data_);
	if(transfers_) {
		transfers_->attach(tickets()
			, [this](data_id const& id, std::optional<error> err) { on_upload_done(id, std::move(err)); }
			, [this](data_id const& id, std::optional<error> err) { on_download_done(id, std::move(err)); });
	}
}

comm::~comm()
{
	// the transfers first: their ticket source is this object
	transfers_.reset();
	fail_ticket_requests(make_error(securepath::errc::invalid_state, "storage connection closed"));
}

void comm::set_output(event_system::event_handler& handler) {
	output_ = &handler;
}

void comm::on_connected() {
	assert(output_);
	{
		std::unique_lock lock{mutex_};
		connected_ = true;
	}
	if(transfers_) {
		transfers_->on_connected();
	}
	output_->emit<comm_events::on_connected>();
}

void comm::on_disconnected(error const& err) {
	assert(output_);
	{
		std::unique_lock lock{mutex_};
		connected_ = false;
	}
	if(transfers_) {
		// what the server got stays there, what arrived here too; the engine asks again
		// after the reconnect
		transfers_->on_disconnected();
	}
	{
		std::unique_lock lock{mutex_};
		uploads_.clear();
		downloads_.clear();
	}
	fail_ticket_requests(err ? err : make_error(securepath::errc::invalid_state, "disconnected from the record server"));
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
			, p.modes.limits(), p.data_endpoints}};
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

void comm::handle(protocol::response_data_ticket const& p) {
	move_only_function<void(util::result<data_grant>)> callback;
	{
		std::unique_lock lock{mutex_};
		auto it = ticket_requests_.find(p.cid);
		if(it != ticket_requests_.end()) {
			callback = std::move(it->second);
			ticket_requests_.erase(it);
		}
	}
	if(callback && p.error) {
		callback(util::result<data_grant>{protocol::to_error(p.error)});
	} else if(callback) {
		callback(util::result<data_grant>{data_grant{p.ticket, p.holders}});
	}
}

ticket_source comm::tickets() {
	return [this](data_descriptor const& d, data_right right, move_only_function<void(util::result<data_grant>)> cb) {
		// registered before the request leaves: the answer may be quicker than this thread
		std::unique_lock lock{mutex_};
		if(!connected_) {
			// a request would go into a connection that is not there: answered here
			lock.unlock();
			cb(util::result<data_grant>{make_error(securepath::errc::invalid_state, "not connected to the record server")});
		} else {
			auto const handle = nc_impl_->request_data_ticket(sid_, d.manifest_digest, right);
			ticket_requests_.emplace(handle, std::move(cb));
		}
	};
}

void comm::fail_ticket_requests(error const& err) {
	std::map<request_handle, move_only_function<void(util::result<data_grant>)>> requests;
	{
		std::unique_lock lock{mutex_};
		requests.swap(ticket_requests_);
	}
	for(auto& [handle, callback] : requests) {
		callback(util::result<data_grant>{err});
	}
}

void comm::handle(protocol::notify_data const& p) {
	assert(output_);
	output_->emit<comm_events::on_data_available>(p.data_id, p.complete);
}

void comm::handle(protocol::notify_equivocation const& p) {
	assert(output_);
	output_->emit<comm_events::on_equivocation>(p.sid, p.proof);
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

request_handle comm::fetch_data(data_id const& id) {
	assert(output_);
	bool is_new = false;
	auto const handle = start_transfer(downloads_, id, is_new);
	if(is_new && transfers_) {
		transfers_->fetch(id);
	} else if(is_new) {
		on_download_done(id, make_error(securepath::errc::not_supported, "the storage keeps no record data"));
	}
	return handle;
}

request_handle comm::commit_record(record_handle h) {
	return nc_impl_->commit_record(sid_, h->record());
}

/// the handle of the data's transfer: the running one, or a new one (is_new)
request_handle comm::start_transfer(transfers& running, data_id const& id, bool& is_new) {
	std::unique_lock lock{mutex_};
	auto it = running.find(id);
	is_new = it == running.end();
	if(is_new) {
		it = running.emplace(id, ++nc_impl_->call_id).first;
	}
	return it->second;
}

std::optional<request_handle> comm::end_transfer(transfers& running, data_id const& id) {
	std::optional<request_handle> handle;
	std::unique_lock lock{mutex_};
	auto it = running.find(id);
	if(it != running.end()) {
		handle = it->second;
		running.erase(it);
	}
	return handle;
}

request_handle comm::upload_data(data_id const& id) {
	assert(output_);
	bool is_new = false;
	auto const handle = start_transfer(uploads_, id, is_new);
	if(is_new && transfers_) {
		transfers_->upload(id);
	} else if(is_new) {
		on_upload_done(id, make_error(securepath::errc::not_supported, "the storage keeps no record data"));
	}
	return handle;
}

void comm::on_upload_done(data_id const& id, std::optional<error> err) {
	if(auto const handle = end_transfer(uploads_, id)) {
		output_->emit<comm_events::on_data_uploaded>(*handle, std::move(err));
	}
}

void comm::on_download_done(data_id const& id, std::optional<error> err) {
	if(auto const handle = end_transfer(downloads_, id)) {
		output_->emit<comm_events::on_data_downloaded>(*handle, std::move(err));
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
