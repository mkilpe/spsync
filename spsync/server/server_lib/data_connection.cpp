#include "data_connection.hpp"

#include <spsync/core/sync_mode.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::sync {

data_connection::data_connection(data_server_context& c)
: context_(c)
{
}

template<typename T>
void data_connection::send_packet(T const& p) {
	send(serialisation::asn_der_serialise_choice<protocol::d2c_types>(p));
}

securepath::error data_connection::on_connect(protocol::data_hello const& p, crypto::public_key_id id) {
	LOG_TRACE("data connection of user {}", id);
	if(p.version != protocol::current_version) {
		LOG_WARN("client {} speaks data protocol version {}, this server {}", id, p.version, protocol::current_version);
		return make_error(protocol::errc::invalid_state, "unsupported protocol version");
	}
	id_ = std::move(id);
	send_packet(protocol::data_hello_reply{p});
	return securepath::error();
}

securepath::error data_connection::check_ticket(data_ticket const& ticket, data_right right) const {
	securepath::error ret;
	auto const& d = ticket.descriptor();
	auto const verified = ticket.verify(context_.keys(), context_.now());
	if(verified.code() == make_error_code(securepath::errc::timeout)) {
		ret = make_error(protocol::errc::data_ticket_expired);
	} else if(verified) {
		LOG_INFO("data ticket of user {} refused: {}", id_, verified);
		ret = make_error(protocol::errc::invalid_data_ticket);
	} else if(!context_.trusted_issuer(ticket.issuer())) {
		LOG_WARN("data ticket of user {} signed by {}, not a record server of this data server", id_, ticket.issuer());
		ret = make_error(protocol::errc::invalid_data_ticket);
	} else if(ticket.member() != id_ || ticket.right() != right) {
		LOG_WARN("data ticket presented by user {} is for {} / another right", id_, ticket.member());
		ret = make_error(protocol::errc::invalid_data_ticket);
	} else if(ticket.storage_id().empty() || d.manifest_digest.empty() || d.chunk_size == 0 || d.chunk_size > max_chunk_size) {
		// a chunk must fit a transport frame whatever the record server signed
		ret = make_error(protocol::errc::invalid_data_ticket);
	}
	return ret;
}

void data_connection::handle(protocol::upload_data_manifest const& p) {
	auto const& sid = p.ticket.storage_id();
	auto const& id = p.ticket.data();
	LOG_TRACE("upload_data_manifest of user {} [sid={}, data_id={}]", id_, to_hex(sid), to_hex(id));
	util::result<have_bitmap> have{check_ticket(p.ticket, data_right::upload)};
	try {
		if(!have.get_error()) {
			auto store = context_.acquire_store(sid);
			have = store->open_upload(p.ticket.descriptor(), p.manifest, context_.now());
			if(have) {
				uploads_[upload_key{sid, id}] = std::move(store);
			}
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while opening an upload: {} (sid={})", err, to_hex(sid));
		have = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while opening an upload: {} (sid={})", ex.what(), to_hex(sid));
		have = make_error(securepath::errc::unknown_error);
	}
	if(have) {
		send_packet(protocol::upload_data_manifest_reply{p.cid, sid, have->octets()});
	} else {
		send_packet(protocol::upload_data_manifest_reply{p.cid, sid, have.get_error()});
	}
}

void data_connection::handle(protocol::upload_data_chunk const& p) {
	util::result<bool> complete{make_error(protocol::errc::no_such_upload)};
	try {
		auto it = uploads_.find(upload_key{p.sid, p.data_id});
		if(it != uploads_.end()) {
			complete = it->second->store_chunk(p.data_id, p.chunk_no, p.bytes, context_.now());
			if(complete && complete.value()) {
				LOG_INFO("data complete [sid={}, data_id={}]", to_hex(p.sid), to_hex(p.data_id));
				uploads_.erase(it);
				context_.announce_complete(p.sid, p.data_id);
			}
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while storing a chunk: {} (sid={})", err, to_hex(p.sid));
		complete = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while storing a chunk: {} (sid={})", ex.what(), to_hex(p.sid));
		complete = make_error(securepath::errc::unknown_error);
	}
	if(complete) {
		send_packet(protocol::upload_data_chunk_reply{p, complete.value()});
	} else {
		send_packet(protocol::upload_data_chunk_reply{p, complete.get_error()});
	}
}

}
