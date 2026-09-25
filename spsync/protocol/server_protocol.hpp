#pragma once

#include "protocol_base.hpp"
#include "wire_modes.hpp"
#include <spsync/core/data/data_ticket.hpp>
#include <spsync/core/records/block_envelope.hpp>
#include <spsync/core/records/equivocation_proof.hpp>

namespace securepath::sync::protocol {
inline namespace v1 {

/// always first packet to negotiate version
struct server_hello : reply_base {
	using reply_base::reply_base;

	int version{current_version};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & version;
	}
};

struct create_storage_reply : reply_base {
	using reply_base::reply_base;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this);
	}
};

struct destroy_storage_reply : reply_base {
	using reply_base::reply_base;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this);
	}
};

struct storage_management_reply : reply_base {
	using reply_base::reply_base;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this);
	}
};

struct response_sequence_number : reply_base {
	using reply_base::reply_base;

	response_sequence_number(storage_request_base const& p, sequence_number seq, wire_modes m = {}, std::vector<data_endpoint> endpoints = {})
	: reply_base(p)
	, sequence(seq)
	, modes(m)
	, data_endpoints(std::move(endpoints))
	{
	}

	sequence_number sequence;

	/// the modes of the storage, wire encoded (0 = unknown), with its limits: the
	/// validity limits (record_data.txt RD10) a client refuses oversized changes by before
	/// committing, and the retention at a history cut (RD9) it prunes its own history by
	wire_modes modes;
	/// the data-role servers of the storage (record_data.txt RD12); empty when it carries no record data
	std::vector<data_endpoint> data_endpoints;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & sequence & modes & data_endpoints;
	}
};

struct response_records : reply_base {
	using reply_base::reply_base;

	response_records(storage_request_base const& p, sequence_number rmax, sequence_number smax, std::deque<chain_block> blocks)
	: reply_base(p)
	, requested_max(rmax)
	, server_max_sequence(smax)
	, records(std::move(blocks))
	{}

	sequence_number requested_max;
	sequence_number server_max_sequence;
	std::deque<chain_block> records;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & requested_max & server_max_sequence & records;
	}
};

struct response_commit : reply_base {
	using reply_base::reply_base;

	response_commit(storage_request_base const& p, sequence_number max, chain_block r, std::optional<block_envelope> env = {})
	: reply_base(p)
	, server_max_sequence(max)
	, record(std::move(r))
	, envelope(std::move(env))
	{}

	sequence_number server_max_sequence;
	std::optional<chain_block> record;
	/// the server signed sequence assignment (when the server has a signing key)
	std::optional<block_envelope> envelope;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & server_max_sequence & record & envelope;
	}
};

/// the ticket and the data servers to use it at, in the order to try them (RD12/RD13)
struct response_data_ticket : reply_base {
	using reply_base::reply_base;

	response_data_ticket(storage_request_base const& p, data_ticket t, std::vector<data_endpoint> h)
	: reply_base(p)
	, ticket(std::move(t))
	, holders(std::move(h))
	{}

	data_ticket ticket;
	std::vector<data_endpoint> holders;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & ticket & holders;
	}
};

struct notify_record {
	notify_record(storage_id sid = {}, chain_block r = {}, std::optional<block_envelope> env = {})
	: sid(std::move(sid))
	, record(std::move(r))
	, envelope(std::move(env))
	{}

	storage_id sid;
	chain_block record;
	/// the server signed sequence assignment (when the server has a signing key)
	std::optional<block_envelope> envelope;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & sid & record & envelope;
	}
};

/**
 * To the listeners of a storage when a data server announced a data of it (RD4/RD13), so
 * a client waiting for the data (remote_not_complete) fetches without polling
 */
struct notify_data {
	notify_data(storage_id sid = {}, octet_vector data_id = {}, bool complete = false)
	: sid(std::move(sid))
	, data_id(std::move(data_id))
	, complete(complete)
	{}

	storage_id sid;
	octet_vector data_id;
	bool complete{};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & sid & data_id & complete;
	}
};

/**
 * To the listeners of a storage when its server found an origin server assigning one
 * sequence to two records (plan 5.4), and to a client starting a session on the storage
 * for every proof held: the application decides what to make of it (the engine stops
 * committing in strict mode)
 */
struct notify_equivocation {
	notify_equivocation(storage_id sid = {}, equivocation_proof p = {})
	: sid(std::move(sid))
	, proof(std::move(p))
	{}

	storage_id sid;
	equivocation_proof proof;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & sid & proof;
	}
};

using serialisation::type_tag;
using s2c_types =
	typelist<type_tag<server_hello, 1>,
			type_tag<create_storage_reply, 2>,
			type_tag<destroy_storage_reply, 3>,
			type_tag<storage_management_reply, 4>,
			type_tag<response_sequence_number, 5>,
			type_tag<response_records, 6>,
			type_tag<response_commit, 8>,
			type_tag<notify_record, 9>,
			type_tag<response_data_ticket, 10>,
			type_tag<notify_data, 11>,
			type_tag<notify_equivocation, 12> >;

}
}

