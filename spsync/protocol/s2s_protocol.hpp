#pragma once

#include "protocol_base.hpp"

#include <spsync/core/origin_head.hpp>
#include <spsync/core/records/block_envelope.hpp>

#include <securepath/crypto/public_key_id.hpp>

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

/// the anti-entropy heads of one storage (the 3.4 table plus the sender's own head)
struct peer_heads : storage_request_base {
	peer_heads(storage_id sid = {}, std::vector<origin_head> h = {})
	: storage_request_base(0, std::move(sid))
	, heads(std::move(h))
	{}

	std::vector<origin_head> heads;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & heads;
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
	, requested_max(p.to)
	, origin_max(origin_max)
	, envelopes(std::move(env))
	{}

	util::sequence_number requested_max;
	/// the highest origin sequence the sender holds for the requested origin
	util::sequence_number origin_max;
	std::deque<block_envelope> envelopes;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & requested_max & origin_max & envelopes;
	}
};

/// commit push (plan 4.2): envelopes the sender just committed as the origin
struct push_records : storage_request_base {
	push_records(storage_id sid = {}, std::deque<block_envelope> env = {})
	: storage_request_base(0, std::move(sid))
	, envelopes(std::move(env))
	{}

	std::deque<block_envelope> envelopes;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & envelopes;
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

using s2s_types = typelist<
			type_tag<peer_hello, 1>,
			type_tag<peer_heads, 2>,
			type_tag<pull_records, 3>,
			type_tag<response_envelopes, 4>,
			type_tag<push_records, 5>,
			type_tag<not_replicating, 6> >;

}
}
