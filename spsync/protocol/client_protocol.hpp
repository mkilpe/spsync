#ifndef SPSYNC_PROTOCOL_CLIENT_PROTOCOL_HEADER
#define SPSYNC_PROTOCOL_CLIENT_PROTOCOL_HEADER

#include "protocol_base.hpp"

#include <securepath/util/typelist.hpp>
#include <securepath/serialisation/choice.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/vector.hpp>

namespace securepath::sync::protocol {
inline namespace v1 {

//client side protocol packets:
// - initial packet with version
// - list storages

// - create storage
// - destroy storage
// - manage storage (request updates, alter settings on server, quota)

// - request sequence number
// - request records
// - request data
// - request commit

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
	create_storage(call_id cid = 0, storage_id sid = {}, std::uint32_t mode = 0, std::uint32_t amode = 0)
	: storage_request_base(cid, std::move(sid))
	, mode(mode)
	, amode(amode)
	{}

	/// requested storage modes, wire encoded (0 = server default); immutable after creation
	std::uint32_t mode{0};
	std::uint32_t amode{0};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & mode & amode;
	}
};

/// Remove storage with specific storage id, this required that you also created it
struct destroy_storage : storage_request_base {
	using storage_request_base::storage_request_base;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this);
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
		seq & static_cast<storage_request_base&>(*this);
	}
};

/// request the current sequence number for storage
struct request_sequence_number : storage_request_base {
	request_sequence_number(call_id cid = 0, storage_id sid = {}, std::uint32_t expected_mode = 0, std::uint32_t expected_amode = 0)
	: storage_request_base(cid, std::move(sid))
	, expected_mode(expected_mode)
	, expected_amode(expected_amode)
	{}

	/// the modes the client expects the storage to have, wire encoded (0 = no check);
	/// the server replies with storage_mode_mismatch when they differ from the storage
	std::uint32_t expected_mode{0};
	std::uint32_t expected_amode{0};

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & expected_mode & expected_amode;
	}
};

/**
 * request records for sequence numbers [start, end].
 * The server will return only some maximum amount of records and the client needs to re-request the rest.
 */
struct request_records : storage_request_base {
	request_records(call_id cid = 0, storage_id sid = {}, util::sequence_number start = {}, util::sequence_number end = {})
	: storage_request_base(cid, sid)
	, start(start)
	, end(end)
	{
	}

	util::sequence_number start, end;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & start & end;
	}
};

struct request_data : storage_request_base {
	util::sequence_number record;
	/// data from position [start, end];
	std::uint64_t start, end;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & record & start & end;
	}
};

struct request_commit : storage_request_base {
	request_commit(call_id cid = 0, storage_id sid = {}, chain_block record = {})
	: storage_request_base(cid, sid)
	, record(record)
	{
	}

	chain_block record;

	template<typename S>
	void serialise(S& s) {
		serialisation::sequence<S> seq(s);
		seq & static_cast<storage_request_base&>(*this) & record;
	}
};

using serialisation::type_tag;
using c2s_types =
	typelist<type_tag<client_hello, 1>,
			type_tag<create_storage, 2>,
			type_tag<destroy_storage, 3>,
			type_tag<storage_management, 4>,
			type_tag<request_sequence_number, 5>,
			type_tag<request_records, 6>,
			type_tag<request_data, 7>,
			type_tag<request_commit, 8> >;

}
}

#endif