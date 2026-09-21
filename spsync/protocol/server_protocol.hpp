#pragma once

#include "protocol_base.hpp"
#include <spsync/core/data/data_ticket.hpp>
#include <spsync/core/records/block_envelope.hpp>

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
	, mode(m.mode)
	, amode(m.amode)
	, repl(m.repl)
	, max_record_size(m.max_record_size)
	, chunk_size(m.chunk_size)
	, kept_data_versions(m.kept_data_versions)
	, data_endpoints(std::move(endpoints))
	{
	}

	sequence_number sequence;

	/// the modes of the storage, wire encoded (0 = unknown)
	std::uint32_t mode{0};
	std::uint32_t amode{0};
	std::uint32_t repl{0};
	/// the validity limits of the storage (record_data.txt RD10): the client refuses
	/// oversized changes before committing
	std::uint32_t max_record_size{0};
	std::uint32_t chunk_size{0};
	/// the retention of the storage at a history cut (record_data.txt RD9): a client
	/// pruning its history lets the data of older versions go alike
	std::uint32_t kept_data_versions{0};
	/// the data-role servers of the storage (record_data.txt RD12); empty when it carries no record data
	std::vector<data_endpoint> data_endpoints;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & sequence & mode & amode & repl & max_record_size & chunk_size
			& kept_data_versions & data_endpoints;
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

struct response_data : reply_base {
	using reply_base::reply_base;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this);
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

using serialisation::type_tag;
using s2c_types =
	typelist<type_tag<server_hello, 1>,
			type_tag<create_storage_reply, 2>,
			type_tag<destroy_storage_reply, 3>,
			type_tag<storage_management_reply, 4>,
			type_tag<response_sequence_number, 5>,
			type_tag<response_records, 6>,
			type_tag<response_data, 7>,
			type_tag<response_commit, 8>,
			type_tag<notify_record, 9>,
			type_tag<response_data_ticket, 10>,
			type_tag<notify_data, 11> >;

}
}

