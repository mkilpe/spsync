#pragma once

#include "protocol_base.hpp"

#include <spsync/core/data/data_manifest.hpp>
#include <spsync/core/data/data_ticket.hpp>
#include <spsync/core/sync_mode.hpp>

#include <securepath/serialisation/codec/asn_der/types.hpp>

namespace securepath::sync::protocol {
inline namespace v1 {

/**
 * The packets between a client and a data-role server (record_data.txt RD4/RD12), on the
 * data listener's own port and inside the encrypted transport like everything else. The
 * data server knows no chain: every transfer starts with a ticket a record server signed.
 * Uploads here; the download packets come with the download path (RDS 6).
 */

/// always the first packet, negotiates the version
struct data_hello : protocol_base {
	using protocol_base::protocol_base;

	int version{current_version};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & version;
	}
};

/**
 * Open the upload of a data or resume it: the ticket states the descriptor the record
 * commits to, the manifest must hash to it. The reply says which chunks are already held.
 */
struct upload_data_manifest : protocol_base {
	upload_data_manifest(call_id cid = 0, data_ticket ticket = {}, data_manifest manifest = {})
	: protocol_base(cid)
	, ticket(std::move(ticket))
	, manifest(std::move(manifest))
	{}

	data_ticket ticket;
	data_manifest manifest;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & ticket & manifest;
	}
};

/**
 * A chunk - the unit at rest, up to max_chunk_size - never travels in one packet: it
 * moves in pieces, so neither side holds more than a piece of it in memory and the size
 * of a chunk is not bound by what a packet may carry. The sender picks the piece size
 * (default below), the receiver takes pieces up to the maximum.
 */
std::uint32_t constexpr default_data_piece_size{128 * 1024};
std::uint32_t constexpr max_data_piece_size{1024 * 1024};

// the piece is one DER octet string: the codec refuses primitives above its limit
static_assert(std::uint64_t{max_data_piece_size} + 64 <= serialisation::max_structure_size);

/**
 * One piece of an encrypted chunk of an upload opened on this connection: bytes of the
 * chunk from offset. The pieces of a chunk come in order from offset 0 (a piece at 0
 * starts the chunk over); the piece that completes the chunk gets it verified against
 * the manifest, and its reply tells whether it was the manifest's chunk.
 */
struct upload_data_chunk : storage_request_base {
	upload_data_chunk(call_id cid = 0, storage_id sid = {}, octet_vector data_id = {}, std::uint64_t chunk_no = 0
		, std::uint64_t offset = 0, octet_vector bytes = {})
	: storage_request_base(cid, std::move(sid))
	, data_id(std::move(data_id))
	, chunk_no(chunk_no)
	, offset(offset)
	, bytes(std::move(bytes))
	{}

	octet_vector data_id;
	std::uint64_t chunk_no{};
	std::uint64_t offset{};
	octet_vector bytes;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & data_id & chunk_no & offset & bytes;
	}
};

struct data_hello_reply : reply_base {
	using reply_base::reply_base;

	int version{current_version};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & version;
	}
};

struct upload_data_manifest_reply : reply_base {
	using reply_base::reply_base;

	upload_data_manifest_reply(call_id cid, storage_id sid, octet_vector have)
	: reply_base(cid, std::move(sid))
	, have(std::move(have))
	{}

	/// the chunks the server holds (have_bitmap octets): the rest is what to send
	octet_vector have;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & have;
	}
};

struct upload_data_chunk_reply : reply_base {
	using reply_base::reply_base;

	upload_data_chunk_reply(storage_request_base const& p, bool complete)
	: reply_base(p)
	, complete(complete)
	{}

	/// true when this piece completed the data
	bool complete{};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & complete;
	}
};

using serialisation::type_tag;
using c2d_types =
	typelist<type_tag<data_hello, 1>,
			type_tag<upload_data_manifest, 2>,
			type_tag<upload_data_chunk, 3> >;

using d2c_types =
	typelist<type_tag<data_hello_reply, 1>,
			type_tag<upload_data_manifest_reply, 2>,
			type_tag<upload_data_chunk_reply, 3> >;

}
}
