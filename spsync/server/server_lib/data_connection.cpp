// SPDX-License-Identifier: MIT

#include "data_connection.hpp"
#include "guarded.hpp"

#include <algorithm>

#include <spsync/core/sync_mode.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

namespace securepath::sync {

data_connection::data_connection(data_server_context& c, data_connection_limits limits)
: context_(c)
, limits_(limits)
{
}

void data_connection::trim_idle(time_point now) {
	auto const idle = [&](auto const& transfer) { return transfer.second.last_used + limits_.transfer_idle_limit < now; };
	std::erase_if(uploads_, idle);
	std::erase_if(downloads_, idle);
}

template<typename Transfer>
void data_connection::make_room(std::map<upload_key, Transfer>& transfers) {
	if(transfers.size() >= limits_.max_transfers && !transfers.empty()) {
		auto const oldest = std::ranges::min_element(transfers, {}, [](auto const& t) { return t.second.last_used; });
		transfers.erase(oldest);
	}
}

std::uint64_t data_connection::staged_bytes() const {
	std::uint64_t ret = 0;
	for(auto const& [key, up] : uploads_) {
		for(auto const& [chunk_no, incoming] : up.incoming) {
			ret += incoming.expected_size();
		}
	}
	return ret;
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
	} else if(ticket.storage_id().empty() || !storable_descriptor(d)) {
		// a chunk must fit a transport frame whatever the record server signed
		ret = make_error(protocol::errc::invalid_data_ticket);
	}
	return ret;
}

securepath::error data_connection::check_download_ticket(data_ticket const& ticket) const {
	// RD13 replication: a data server that is to hold a copy pulls like a member, with
	// a ticket of its own right
	return check_ticket(ticket, ticket.right() == data_right::replicate ? data_right::replicate : data_right::download);
}

void data_connection::handle(protocol::upload_data_manifest const& p) {
	auto const& sid = p.ticket.storage_id();
	auto const& id = p.ticket.data();
	LOG_TRACE("upload_data_manifest of user {} [sid={}, data_id={}]", id_, to_hex(sid), to_hex(id));
	trim_idle(context_.now());
	auto const have = guarded("opening an upload", sid, [&]() -> util::result<have_bitmap> {
		if(auto const refused = check_ticket(p.ticket, data_right::upload)) {
			return refused;
		}
		auto store = context_.acquire_store(sid);
		auto opened = store->open_upload(p.ticket.descriptor(), p.manifest, context_.now());
		if(opened) {
			// a manifest again starts the upload over on this connection: partial chunks go
			uploads_.erase(upload_key{sid, id});
			make_room(uploads_);
			uploads_[upload_key{sid, id}] = upload{std::move(store), {}, context_.now()};
		}
		return opened;
	});
	send_packet(have ? protocol::upload_data_manifest_reply{p.cid, sid, have.value().octets()}
		: protocol::upload_data_manifest_reply{p.cid, sid, have.get_error()});
}

/**
 * The pieces of a chunk come in order from offset 0 and are appended to a staged file as
 * they come; the piece that completes the chunk gets the whole verified against the
 * manifest. Whatever breaks that - a gap, an overrun, a piece above the limit, the wrong
 * bytes in the end - loses the chunk: invalid_data_chunk, the sender starts it over.
 */
util::result<bool> data_connection::take_piece(upload& up, protocol::upload_data_chunk const& p) {
	util::result<bool> ret{make_error(protocol::errc::invalid_data_chunk)};
	up.last_used = context_.now();
	if(p.offset == 0) {
		up.incoming.erase(p.chunk_no);
		if(up.incoming.size() < max_incoming_chunks) {
			auto begun = up.store->begin_chunk(p.data_id, p.chunk_no, context_.now());
			// a chunk on its way takes its whole size on disk once it is in: bounded over
			// every upload of the connection, in octets; one over the limit is not begun
			bool const room = begun && staged_bytes() + begun.value().expected_size() <= limits_.max_staged_bytes;
			if(room) {
				up.incoming.emplace(p.chunk_no, std::move(begun.value()));
			} else if(!begun) {
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
	trim_idle(context_.now());
	auto const complete = guarded("storing a chunk", p.sid, [&]() -> util::result<bool> {
		auto it = uploads_.find(upload_key{p.sid, p.data_id});
		if(it == uploads_.end()) {
			return make_error(protocol::errc::no_such_upload);
		}
		auto taken = take_piece(it->second, p);
		if(taken && taken.value()) {
			LOG_INFO("data complete [sid={}, data_id={}]", to_hex(p.sid), to_hex(p.data_id));
			uploads_.erase(it);
			context_.announce_complete(p.sid, p.data_id);
		}
		return taken;
	});
	send_packet(complete ? protocol::upload_data_chunk_reply{p, complete.value()}
		: protocol::upload_data_chunk_reply{p, complete.get_error()});
}

void data_connection::handle(protocol::download_data_open const& p) {
	auto const& sid = p.ticket.storage_id();
	auto const& id = p.ticket.data();
	LOG_TRACE("download_data_open of user {} [sid={}, data_id={}]", id_, to_hex(sid), to_hex(id));
	trim_idle(context_.now());
	auto served = guarded("opening a download", sid, [&]() -> util::result<served_data> {
		if(auto const refused = check_download_ticket(p.ticket)) {
			return refused;
		}
		auto store = context_.acquire_store(sid);
		auto opened = store->open_download(p.ticket.descriptor());
		if(opened) {
			downloads_.erase(upload_key{sid, id});
			make_room(downloads_);
			downloads_[upload_key{sid, id}] = download{std::move(store), p.ticket.right() != data_right::replicate, context_.now()};
		}
		return opened;
	});
	send_packet(served ? protocol::download_data_open_reply{p.cid, sid, std::move(served.value().manifest), served.value().have.octets()}
		: protocol::download_data_open_reply{p.cid, sid, served.get_error()});
}

void data_connection::handle(protocol::download_data_piece const& p) {
	std::uint32_t retry_after = 0;
	trim_idle(context_.now());
	auto piece = guarded("serving a piece", p.sid, [&]() -> util::result<octet_vector> {
		auto it = downloads_.find(upload_key{p.sid, p.data_id});
		if(it == downloads_.end()) {
			return make_error(protocol::errc::data_not_held);
		}
		it->second.last_used = context_.now();
		auto const& [store, charged, last_used] = it->second;
		auto served = store->serve_piece(p.data_id, p.chunk_no, p.offset, p.size, context_.now(), charged);
		if(served.get_error().code() == make_error_code(protocol::errc::data_transfer_quota_exceeded)) {
			retry_after = store->retry_after(context_.now());
		}
		return served;
	});
	if(piece) {
		send_packet(protocol::download_data_piece_reply{p, std::move(piece.value())});
	} else {
		protocol::download_data_piece_reply reply{p, piece.get_error()};
		reply.retry_after = retry_after;
		send_packet(reply);
	}
}

}
