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
// list storages

// create storage
// destroy storage
// manage storage (request updates, alter settings on server, quota)

// request sequence number
// request records
// request data
// request commit

/// always first packet to negotiate version
struct client_hello : protocol_base {
	using protocol_base::protocol_base;

	int version{current_version};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & version;
	}
};

/// Create storage with specific storage id
struct create_storage : storage_request_base {
	using protocol_base::protocol_base;

	//chain_block initial_record;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this);
	}
};

/// Remove storage with specific storage id, this required that you also created it
struct destroy_storage : storage_request_base {
	using protocol_base::protocol_base;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this);
	}
};

/// place holder for later storage management functionality
struct storage_management : storage_request_base {
	// switch flag if automatic record updates are received
	// quota handling
	// list members in storage

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this);
	}
};

/// request the current sequence number for storage
struct request_sequence_number : storage_request_base {

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this);
	}
};

/**
 * request records for sequence numbers [start, end].
 * The server will return only some maximum amount of records and the client needs to re-request the rest.
 */
struct request_records : storage_request_base {
	sequence_number start, end;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & start & end;
	}
};

struct request_data : storage_request_base {
	sequence_number record;
	std::uint64_t start, end;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & record & start & end;
	}
};

struct request_commit : storage_request_base {
	chain_block record;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<protocol_base&>(*this) & record;
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