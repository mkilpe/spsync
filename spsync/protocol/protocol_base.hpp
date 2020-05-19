#ifndef SPSYNC_PROTOCOL_PROTOCOL_BASE_HEADER
#define SPSYNC_PROTOCOL_PROTOCOL_BASE_HEADER

#include "types.hpp"

#include <securepath/util/typelist.hpp>
#include <securepath/serialisation/choice.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/vector.hpp>

namespace securepath::sync::protocol {
inline namespace v1 {

std::uint16_t const current_version{1};

using storage_id = octet_vector;
using call_id = std::uint32_t;

/// common data for all protocol packets
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

/// common data for all storage specific requests
struct storage_request_base : protocol_base {
	storage_request_base(call_id cid = 0, storage_id sid = {})
	: protocol_base(cid)
	, sid(std::move(sid))
	{}

	storage_id sid;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & sid;
	}
};

}

#endif