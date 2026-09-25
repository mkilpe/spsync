// SPDX-License-Identifier: MIT

#include "record_server_link.hpp"

#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>

namespace securepath::sync {

record_server_link::record_server_link(network::context& context, peer_config record_server, crypto::public_key_id own_id, hooks h
	, std::chrono::seconds silence_limit)
: encrypted_connection(context)
, record_server_(std::move(record_server))
, own_id_(std::move(own_id))
, hooks_(std::move(h))
, silence_limit_(silence_limit)
, silence_(context.io_context())
{
}

record_server_link::~record_server_link() {
	close();
	// close() tells nobody: whoever still waits for a ticket is answered here
	fail_requests(make_error(securepath::errc::invalid_state, "the link to the record server is gone"));
}

void record_server_link::start(std::chrono::seconds timeout) {
	LOG_INFO("connecting to record server {}", record_server_);
	connect(record_server_.host, record_server_.port, timeout);
	watch();
}

void record_server_link::close() {
	{
		std::unique_lock lock{mutex_};
		silence_.cancel();
	}
	encrypted_connection::close();
}

void record_server_link::watch() {
	std::unique_lock lock{mutex_};
	silence_.expires_after(std::chrono::duration_cast<std::chrono::milliseconds>(silence_limit_) / 2);
	silence_.async_wait([weak = weak_from_this()](std::error_code const& ec) {
		auto self = weak.lock();
		if(self && !ec && self->check_overdue()) {
			self->watch();
		}
	});
}

bool record_server_link::check_overdue() {
	std::vector<ticket_callback> overdue;
	bool ready{};
	{
		std::unique_lock lock{mutex_};
		ready = ready_;
		overdue = requests_.take_older_than(silence_limit_);
	}
	auto const err = make_error(securepath::errc::timeout, "the record server did not answer a ticket request");
	for(auto& answer : overdue) {
		answer(err);
	}
	if(!overdue.empty()) {
		// a record server that does not answer is one to connect to anew: on_disconnected
		// comes on the strand and tells the owner
		LOG_WARN("record server {} did not answer {} ticket requests in time, link given up", record_server_, overdue.size());
		encrypted_connection::close_later(err, shared_from_this());
	}
	return overdue.empty() && ready;
}

bool record_server_link::ready() const {
	std::unique_lock lock{mutex_};
	return ready_;
}

void record_server_link::send_packet(auto const& packet) {
	encrypted_connection::send(serialisation::asn_der_serialise_choice<protocol::s2s_types>(packet));
}

void record_server_link::announce(protocol::announce_data const& p) {
	if(ready()) {
		send_packet(p);
	}
}

void record_server_link::request_ticket(protocol::storage_id const& sid, data_id const& id, ticket_callback answer) {
	protocol::call_id cid = 0;
	{
		std::unique_lock lock{mutex_};
		if(ready_) {
			cid = next_call_++;
			requests_.add(cid, std::move(answer));
		}
	}
	if(cid != 0) {
		send_packet(protocol::request_replica_ticket{cid, sid, id});
	} else {
		answer(make_error(securepath::errc::invalid_state, "no link to the record server"));
	}
}

void record_server_link::fail_requests(securepath::error const& err) {
	std::vector<ticket_callback> requests;
	{
		std::unique_lock lock{mutex_};
		requests = requests_.take_all();
	}
	for(auto& answer : requests) {
		answer(err);
	}
}

void record_server_link::on_connected() {
	if(remote_key_id() != record_server_.key) {
		LOG_WARN("record server {} authenticated with another key than configured", record_server_);
		encrypted_connection::close();
		on_disconnected(make_error(protocol::errc::invalid_client_key));
	} else {
		deser_.clear();
		send_packet(protocol::peer_hello{own_id_});
	}
}

void record_server_link::on_disconnected(securepath::error const& err) {
	LOG_INFO("record server {} disconnected: {}", record_server_, err);
	{
		std::unique_lock lock{mutex_};
		ready_ = false;
	}
	fail_requests(make_error(securepath::errc::invalid_state, "the link to the record server went down"));
	if(hooks_.disconnected) {
		hooks_.disconnected();
	}
}

void record_server_link::on_received(octet_span s) {
	try {
		deser_.handle(s, std::ref(*this));
	} catch(std::exception const& ex) {
		LOG_WARN("bad packet from record server {}: {}", record_server_, ex.what());
		encrypted_connection::close();
		on_disconnected(make_error(securepath::errc::invalid_data));
	}
}

void record_server_link::operator()(protocol::peer_hello const& p) {
	if(p.server_id != record_server_.key || p.version != protocol::s2s_current_version) {
		LOG_WARN("record server {} says hello as somebody else or in another version", record_server_);
		encrypted_connection::close();
		on_disconnected(make_error(protocol::errc::invalid_state));
	} else {
		if(auto key = remote_public_key(); key && hooks_.trust) {
			hooks_.trust(*key);
		}
		{
			std::unique_lock lock{mutex_};
			ready_ = true;
		}
		if(hooks_.connected) {
			hooks_.connected();
		}
		// RD13: the availability table over there is transient, it gets the whole view
		for(auto const& announcement : hooks_.whole_view()) {
			send_packet(announcement);
		}
	}
}

void record_server_link::operator()(protocol::release_data const& p) {
	// the link is to a configured record server whose key the handshake verified
	if(ready() && hooks_.release) {
		hooks_.release(p.sid, p.data_ids);
	}
}

void record_server_link::operator()(protocol::replicate_data const& p) {
	if(ready() && hooks_.replicate) {
		hooks_.replicate(p.sid, p.descriptors);
	}
}

void record_server_link::operator()(protocol::response_replica_ticket const& p) {
	std::optional<ticket_callback> answer;
	{
		std::unique_lock lock{mutex_};
		answer = requests_.take(p.cid);
	}
	if(answer && p.error) {
		(*answer)(protocol::to_error(p.error));
	} else if(answer) {
		(*answer)(data_grant{p.ticket, p.holders});
	}
}

}
