#ifndef SPSYNC_PROTOCOL_CLIENT_PROTOCOL_HEADER
#define SPSYNC_PROTOCOL_CLIENT_PROTOCOL_HEADER

#include "protocol_base.hpp"

#include <securepath/util/typelist.hpp>
#include <securepath/serialisation/choice.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/vector.hpp>

namespace securepath::sync::protocol {
inline namespace v1 {

// initial packet with version
// create storage
// destroy storage
// list storages
// manage storage (request updates, alter settings on server)
// request sequence number
// request records
// request data
// request commit

struct client_hello : protocol_base {
	using protocol_base::protocol_base;

	int version{current_version};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & version;
	}
};

struct storage_management : protocol_base {
	std::vector<storage_management_info> storages;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & storages;
	}
};


struct request_sequence_number : storage_request_base {

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
	}
};

struct request_records : storage_request_base {
	sequence_number start, end;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & start & end;
	}
};

struct request_data : storage_request_base {
	sequence_number record;
	std::uint64_t start, end;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & record & start & end;
	}
};

struct request_commit : storage_request_base {
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