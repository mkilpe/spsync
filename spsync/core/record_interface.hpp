#ifndef SPSYNC_CORE_RECORD_INTERFACE_HEADER
#define SPSYNC_CORE_RECORD_INTERFACE_HEADER

#include "types.hpp"
#include <spsync/core/records/record.hpp>

#include <memory>

namespace securepath::sync {

//q: how to handle incoming records which have not yet checked for authenticity
enum class record_state {
	unknown = 0,

	/// the record is waiting commit
	pending_commit,

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
	virtual ~record_interface() = default;

	//get the record structure out
	//set/get the record state (pending commit, committed, ...?)
	//get data handle or alternatively read/write

	// data size
	// data blocks we have
	// read/write data (plain and encrypted?)

	// remove data

	virtual record_tag tag() const = 0;
	virtual record_state state() const = 0;
};

using record_handle = std::shared_ptr<record_interface>;

}

#endif
