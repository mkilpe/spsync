#pragma once

#include "protocol_base.hpp"

#include <spsync/core/origin_head.hpp>
#include <spsync/core/records/block_envelope.hpp>
#include <spsync/core/sync_mode.hpp>

#include <securepath/crypto/public_key.hpp>
#include <securepath/crypto/public_key_id.hpp>

#include <optional>

namespace securepath::sync::protocol {
inline namespace v1 {

/**
 * The server-to-server packet family (plan 4.1). Peers talk over the encrypted
 * transport with the pk handshake and authenticate each other by the server signing
 * key ids from the peer configuration (3.3). Requests reuse the storage_request_base /
 * reply_base correlation of the client protocol.
 */

std::uint16_t const s2s_current_version{1};

/// first packet in both directions after the transport is up
struct peer_hello : protocol_base {
	peer_hello(crypto::public_key_id id = {}, std::uint16_t v = s2s_current_version)
	: server_id(std::move(id))
	, version(v)
	{}

	/// the sender's server signing key id; must match the transport key
	crypto::public_key_id server_id;
	std::uint16_t version{s2s_current_version};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & server_id & version;
	}
};

/**
 * The anti-entropy heads of one storage (the 3.4 table plus the sender's own head). The
 * storage modes ride along so a replica that does not hold the storage yet can create
 * it with the same modes (a chat created on one replica appears on the others).
 */
struct peer_heads : storage_request_base {
	peer_heads(storage_id sid = {}, std::vector<origin_head> h = {}, std::optional<storage_modes> m = {})
	: storage_request_base(0, std::move(sid))
	, heads(std::move(h))
	, modes(to_wire(m))
	{}

	std::vector<origin_head> heads;
	wire_modes modes;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & heads & modes.mode & modes.amode & modes.repl
			& modes.max_record_size & modes.chunk_size & modes.kept_data_versions;
	}
};

/// pull the records of one origin in origin-local sequence order [from, to]
struct pull_records : storage_request_base {
	pull_records(call_id cid = 0, storage_id sid = {}, crypto::public_key_id o = {},
		util::sequence_number from = {}, util::sequence_number to = {})
	: storage_request_base(cid, std::move(sid))
	, origin(std::move(o))
	, from(from)
	, to(to)
	{}

	crypto::public_key_id origin;
	util::sequence_number from, to;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & origin & from & to;
	}
};

/// reply to pull_records: the response_records shape with envelopes instead of blocks
struct response_envelopes : reply_base {
	using reply_base::reply_base;

	response_envelopes(pull_records const& p, util::sequence_number origin_max, std::deque<block_envelope> env)
	: reply_base(p)
	, origin(p.origin)
	, requested_max(p.to)
	, origin_max(origin_max)
	, envelopes(std::move(env))
	{}

	/// the pulled origin (the puller's continuation loop keys on it, plan 4.4)
	crypto::public_key_id origin;
	util::sequence_number requested_max;
	/// the highest origin sequence the sender holds for the requested origin
	util::sequence_number origin_max;
	std::deque<block_envelope> envelopes;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & origin & requested_max & origin_max & envelopes;
	}
};

/// commit push (plan 4.2): envelopes the sender just committed as the origin; the
/// storage modes let a replica create the storage on first contact (as in peer_heads)
struct push_records : storage_request_base {
	push_records(storage_id sid = {}, std::deque<block_envelope> env = {}, std::optional<storage_modes> m = {})
	: storage_request_base(0, std::move(sid))
	, envelopes(std::move(env))
	, modes(to_wire(m))
	{}

	std::deque<block_envelope> envelopes;
	wire_modes modes;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & envelopes & modes.mode & modes.amode & modes.repl
			& modes.max_record_size & modes.chunk_size & modes.kept_data_versions;
	}
};

/// the storage modes carried in a peer packet, if any
inline std::optional<storage_modes> peer_modes(wire_modes const& m) {
	return modes_from_wire(m);
}

/**
 * Ask the peer for a public key it holds (plan 5.2): a replica bootstrapping a storage
 * meets record signers it never saw (their clients registered elsewhere); the peer that
 * accepted the record has the key. Public keys are self authenticating (id = hash).
 */
struct request_key : protocol_base {
	request_key(call_id cid = 0, crypto::public_key_id k = {})
	: protocol_base(cid)
	, key(std::move(k))
	{}

	crypto::public_key_id key;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & key;
	}
};

/// answer to request_key; the key is absent when the peer does not hold it either
struct response_key : protocol_base {
	response_key(call_id cid = 0, std::optional<crypto::public_key> k = {})
	: protocol_base(cid)
	, key(std::move(k))
	{}

	std::optional<crypto::public_key> key;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & key;
	}
};

/// the sender does not replicate the storage (answer to heads/pull/push for it)
struct not_replicating : storage_request_base {
	using storage_request_base::storage_request_base;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this);
	}
};

/// what a data-role server holds of one data (record_data.txt RD13)
struct data_holding_entry {
	storage_id sid;
	octet_vector data_id;
	std::uint64_t have_chunks{};
	std::uint64_t total_chunks{};
	bool complete{};

	bool operator==(data_holding_entry const&) const = default;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & sid & data_id & have_chunks & total_chunks & complete;
	}
};

/**
 * Availability announcement (RD13): what the data role of the holder has, with its load
 * signals. Sent to the peers when a data completes and as a whole when a link comes up;
 * the receivers feed their availability table, from which ticket answers order holders.
 */
struct announce_data : protocol_base {
	announce_data(crypto::public_key_id h = {}, std::vector<data_holding_entry> e = {}, std::uint64_t stored = 0, std::uint32_t uploads = 0)
	: holder(std::move(h))
	, entries(std::move(e))
	, stored_bytes(stored)
	, uploads_in_progress(uploads)
	{}

	/// key id of the data server the entries are about
	crypto::public_key_id holder;
	std::vector<data_holding_entry> entries;
	/// load signals of the holder: what it stores and what is coming in
	std::uint64_t stored_bytes{};
	std::uint32_t uploads_in_progress{};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & holder & entries & stored_bytes & uploads_in_progress;
	}
};

/**
 * From a record server to the data servers of a storage (record_data.txt RD9): no record
 * of the storage names these data any more - a history cut or a rollback took the
 * records - so their chunks may go. Sent on the link a data server keeps to the record
 * server; a data server takes it from a record server it is configured with only.
 */
struct release_data : storage_request_base {
	release_data(storage_id sid = {}, std::vector<octet_vector> ids = {})
	: storage_request_base(0, std::move(sid))
	, data_ids(std::move(ids))
	{}

	std::vector<octet_vector> data_ids;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & data_ids;
	}
};

using s2s_types = typelist<
			type_tag<peer_hello, 1>,
			type_tag<peer_heads, 2>,
			type_tag<pull_records, 3>,
			type_tag<response_envelopes, 4>,
			type_tag<push_records, 5>,
			type_tag<not_replicating, 6>,
			type_tag<request_key, 7>,
			type_tag<response_key, 8>,
			type_tag<announce_data, 9>,
			type_tag<release_data, 10> >;

}
}
