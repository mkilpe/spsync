#ifndef SPSYNC_PROTOCOL_CLIENT_PROTOCOL_HEADER
#define SPSYNC_PROTOCOL_CLIENT_PROTOCOL_HEADER

#include "types.hpp"

#include <securepath/util/typelist.hpp>
#include <securepath/serialisation/choice.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/vector.hpp>

namespace securepath::sync::protocol {
inline namespace v1 {

std::uint16_t const current_version{1};

using call_id = std::uint32_t;

struct protocol_base {
	protocol_base(call_id cid = 0)
	: cid(cid)
	{}

	call_id cid;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & cid;
	}
};

struct client_hello : protocol_base {

	int version{current_version};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & version;
	}
};

struct request_sequence_number : protocol_base {

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
	}
};

struct request_records : protocol_base {
	sequence_number start, end;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & start & end;
	}
};

struct request_data : protocol_base {
	sequence_number record;
	std::uint64_t start, end;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & record & start & end;
	}
};

struct request_commit : protocol_base {
	chain_block record;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & record;
	}
};

using serialisation::type_tag;
using c2s_types =
	typelist<type_tag<client_hello, 1>,
			type_tag<request_sequence_number, 2>,
			type_tag<request_records, 3>,
			type_tag<request_data, 4>,
			type_tag<request_commit, 5> >;

}
}

#endif