#ifndef SPSYNC_PROTOCOL_SERVER_PROTOCOL_HEADER
#define SPSYNC_PROTOCOL_SERVER_PROTOCOL_HEADER

#include "protocol_base.hpp"

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

	response_sequence_number(storage_request_base const& p, sequence_number seq, std::uint32_t mode = 0, std::uint32_t amode = 0, std::uint32_t repl = 0)
	: reply_base(p)
	, sequence(seq)
	, mode(mode)
	, amode(amode)
	, repl(repl)
	{
	}

	sequence_number sequence;

	/// the modes of the storage, wire encoded (0 = unknown)
	std::uint32_t mode{0};
	std::uint32_t amode{0};
	std::uint32_t repl{0};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & sequence & mode & amode & repl;
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

	response_commit(storage_request_base const& p, sequence_number max, chain_block r)
	: reply_base(p)
	, server_max_sequence(max)
	, record(std::move(r))
	{}

	sequence_number server_max_sequence;
	std::optional<chain_block> record;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & server_max_sequence & record;
	}
};

struct notify_record {
	notify_record(storage_id sid = {}, chain_block r = {})
	: sid(std::move(sid))
	, record(std::move(r))
	{}

	storage_id sid;
	chain_block record;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & sid & record;
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
			type_tag<notify_record, 9> >;

}
}

#endif