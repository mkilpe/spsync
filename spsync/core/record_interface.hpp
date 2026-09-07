#pragma once

#include "chain_block_id.hpp"
#include <spsync/util/format.hpp>
#include "record_data.hpp"
#include "types.hpp"
#include <spsync/core/records/chain_block.hpp>

#include <memory>
#include <iosfwd>

namespace securepath::sync {

using record_internal_id = std::uint64_t;

enum class record_state : std::int64_t {
	unknown = 0,

	/// the record is invalid, e.g. the aes gcm tag doesn't match
	invalid,

	/// the record is waiting commit
	pending_commit,

	/// the record received from server but some blocks missing in between to form a chain
	pending_sync,

	/// synchronised with the server (durable; on a single server this is set directly)
	in_sync,

	/**
	 * accepted by a server but not yet durable (see plan D8: quorum in strict mode,
	 * local durability in weak modes). On a single server the engine moves
	 * acked -> in_sync in the same step. Values are stored in the database: only
	 * append states, never renumber.
	 */
	acked
};

/// acked and in_sync both carry a server assigned sequence: the record is confirmed by the server
inline bool is_server_confirmed(record_state state) {
	return state == record_state::in_sync || state == record_state::acked;
}

/// returns true if in good state, ie. not unknown or invalid
bool is_valid_state(record_state);

std::string to_string(record_state);
std::ostream& operator<<(std::ostream&, record_state);

/**
 * Interface for stored records
 *
 * This interface is thread safe
 */
class record_interface {
public:
	//q: should we have state/error stored to indicate what went wrong for pending_sync/invalid states?

	virtual ~record_interface() = default;

	/// Get the chain block id of this record if set by server, otherwise invalid chain_block_id
	virtual chain_block_id block_id() const = 0;

	/// The unique tag to identify this record
	virtual record_tag tag() const = 0;

	/// The hash of block before this one in the chain
	virtual octet_vector parent_block_hash() const = 0;

	/// State of this record
	virtual record_state state() const = 0;

	/// Set the state of this record with optional server provided data. Empty server data does not set anything.
	virtual void set_state(record_state, chain_block_id = {}, octet_vector parent_block_hash = {}) = 0;

	/// Handle to the record data
	//t: we need to have enumeration here as one record can have many entities with data
	//q: perhaps have find for object id
	//q: we need more than just the data, also the metadata and other change record info
	//virtual record_data_handle data() = 0;
	//virtual const_record_data_handle data() const = 0;

	/// Get the type of record
	virtual record_type_tag type() const = 0;

	/// Get the record in serialised formats
	virtual chain_block record() const = 0;

	/// Set the record data, this used in case the record is changed due to being out of sync
	virtual void set_record(chain_block const&) = 0;

	/**
	 * Store the serialised server signed sequence assignment (block_envelope) for this
	 * record. origin/origin_seq index the assignment by its origin server (plan 4.4:
	 * anti-entropy pulls records by origin-local sequence); empty leaves them unset.
	 */
	virtual void set_assignment(octet_vector const&, octet_vector const& origin = {},
		sequence_number origin_seq = {}) = 0;

	/// The serialised server signed sequence assignment, empty when none was received
	virtual octet_vector assignment() const = 0;

	/// Locally unique id for this record. This id stays the same when updating records in case of conflicting state and so can be used to track non-committed records
	/// This is strictly increasing as function of created records
	virtual record_internal_id internal_id() const = 0;
};

using record_handle = std::shared_ptr<record_interface>;

}


SPSYNC_FORMAT_VIA_TO_STRING(securepath::sync::record_state)

