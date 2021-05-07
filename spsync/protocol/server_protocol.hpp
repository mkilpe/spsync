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

	response_sequence_number(protocol_base const& p, sequence_number seq)
	: reply_base(p)
	, sequence(seq)
	{
	}

	sequence_number sequence;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & sequence;
	}
};

struct response_records : reply_base {
	using reply_base::reply_base;

	response_records(protocol_base const& p, std::deque<chain_block> blocks)
	: reply_base(p)
	, records(std::move(blocks))
	{}

	std::deque<chain_block> records;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & records;
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

	response_commit(protocol_base const& p, chain_block r)
	: reply_base(p)
	, record(std::move(r))
	{}

	std::optional<chain_block> record;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<reply_base&>(*this) & record;
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
			type_tag<response_commit, 8> >;

}
}

#endif