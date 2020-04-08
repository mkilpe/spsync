#ifndef SPSYNC_CORE_RECORD_INTERFACE_HEADER
#define SPSYNC_CORE_RECORD_INTERFACE_HEADER

#include "chain_block_id.hpp"
#include "record_data.hpp"
#include "types.hpp"
#include <spsync/core/records/chain_block.hpp>

#include <memory>

namespace securepath::sync {

enum class record_state {
	unknown = 0,

	/// the record is waiting commit
	pending_commit,

	/// the record received from server but some blocks missing in between to form a chain
	pending_sync,

	/// synchronised with the server
	in_sync,

	/// the record is invalid, e.g. the aes gcm tag doesn't match
	invalid
};

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

	/// Set the state of this record
	virtual void set_state(record_state) = 0;

	/// Set the state of this record to in_sync along with the given data
	virtual void set_in_sync(chain_block_id, octet_vector parent_block_hash) = 0;

	/// Handle to the record data
	//t: we need to have enumeration here as one record can have many entities with data
	//q: perhaps have find for object id
	//q: we need more than just the data, also the metadata and other change record info
	//virtual record_data_handle data() = 0;
	//virtual const_record_data_handle data() const = 0;

	/// Get the record in serialised formats
	virtual chain_block record() const = 0;
};

using record_handle = std::shared_ptr<record_interface>;

}

#endif
