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
	} else if(ticket.storage_id().empty() || d.manifest_digest.empty() || d.chunk_size == 0 || d.chunk_size > chunk_size_range.highest) {
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
				// a manifest again starts the upload over on this connection: partial chunks go
				uploads_.erase(upload_key{sid, id});
				uploads_[upload_key{sid, id}].store = std::move(store);
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

/**
 * The pieces of a chunk come in order from offset 0 and are appended to a staged file as
 * they come; the piece that completes the chunk gets the whole verified against the
 * manifest. Whatever breaks that - a gap, an overrun, a piece above the limit, the wrong
 * bytes in the end - loses the chunk: invalid_data_chunk, the sender starts it over.
 */
util::result<bool> data_connection::take_piece(upload& up, protocol::upload_data_chunk const& p) {
	util::result<bool> ret{make_error(protocol::errc::invalid_data_chunk)};
	if(p.offset == 0) {
		up.incoming.erase(p.chunk_no);
		if(up.incoming.size() < max_incoming_chunks) {
			auto begun = up.store->begin_chunk(p.data_id, p.chunk_no, context_.now());
			if(begun) {
				up.incoming.emplace(p.chunk_no, std::move(begun.value()));
			} else {
				ret = begun.get_error();
			}
		}
	}
	auto it = up.incoming.find(p.chunk_no);
	if(it != up.incoming.end()) {
		bool const fits = p.bytes.size() <= protocol::max_data_piece_size;
		if(!fits || !it->second.append(p.offset, p.bytes)) {
			up.incoming.erase(it);
		} else if(it->second.complete()) {
			ret = up.store->finish_chunk(p.data_id, it->second, context_.now());
			up.incoming.erase(it);
		} else {
			ret = false;
		}
	}
	return ret;
}

void data_connection::handle(protocol::upload_data_chunk const& p) {
	util::result<bool> complete{make_error(protocol::errc::no_such_upload)};
	try {
		auto it = uploads_.find(upload_key{p.sid, p.data_id});
		if(it != uploads_.end()) {
			complete = take_piece(it->second, p);
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

void data_connection::handle(protocol::download_data_open const& p) {
	auto const& sid = p.ticket.storage_id();
	auto const& id = p.ticket.data();
	LOG_TRACE("download_data_open of user {} [sid={}, data_id={}]", id_, to_hex(sid), to_hex(id));
	util::result<served_data> served{check_ticket(p.ticket, data_right::download)};
	try {
		if(!served.get_error()) {
			auto store = context_.acquire_store(sid);
			served = store->open_download(p.ticket.descriptor());
			if(served) {
				downloads_[upload_key{sid, id}] = std::move(store);
			}
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while opening a download: {} (sid={})", err, to_hex(sid));
		served = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while opening a download: {} (sid={})", ex.what(), to_hex(sid));
		served = make_error(securepath::errc::unknown_error);
	}
	if(served) {
		send_packet(protocol::download_data_open_reply{p.cid, sid, std::move(served->manifest), served->have.octets()});
	} else {
		send_packet(protocol::download_data_open_reply{p.cid, sid, served.get_error()});
	}
}

void data_connection::handle(protocol::download_data_piece const& p) {
	util::result<octet_vector> piece{make_error(protocol::errc::data_not_held)};
	std::uint32_t retry_after = 0;
	try {
		auto it = downloads_.find(upload_key{p.sid, p.data_id});
		if(it != downloads_.end()) {
			piece = it->second->serve_piece(p.data_id, p.chunk_no, p.offset, p.size, context_.now());
			if(piece.get_error().code() == make_error_code(protocol::errc::data_transfer_quota_exceeded)) {
				retry_after = it->second->retry_after(context_.now());
			}
		}
	} catch(securepath::error const& err) {
		LOG_WARN("exception while serving a piece: {} (sid={})", err, to_hex(p.sid));
		piece = err;
	} catch(std::exception const& ex) {
		LOG_WARN("exception while serving a piece: {} (sid={})", ex.what(), to_hex(p.sid));
		piece = make_error(securepath::errc::unknown_error);
	}
	if(piece) {
		send_packet(protocol::download_data_piece_reply{p, std::move(piece.value())});
	} else {
		protocol::download_data_piece_reply reply{p, piece.get_error()};
		reply.retry_after = retry_after;
		send_packet(reply);
	}
}

}
