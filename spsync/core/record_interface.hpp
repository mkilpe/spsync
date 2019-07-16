#ifndef SPSYNC_CORE_RECORD_INTERFACE_HEADER
#define SPSYNC_CORE_RECORD_INTERFACE_HEADER

#include "record_data.hpp"
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

	/// Get the sequence number of this record if set by server, otherwise invalid sequence_number
	virtual sequence_number seq() const = 0;

	/// The unique tag to identify this record
	virtual record_tag tag() const = 0;

	/// The tag of previous record
	virtual record_tag previous_tag() const = 0;

	/// State of this record
	virtual record_state state() const = 0;

	/// Set the state of this record
	virtual void set_state(record_state, sequence_number server_seq = {}) = 0;

	/// Set object id for data change record
	virtual void set_oid(octet_vector const& oid) = 0;

	/// Handle to the record data
	virtual record_data_handle data() = 0;
	virtual const_record_data_handle data() const = 0;

	/// Get the record in serialised format
	virtual serialised_record record() const = 0;
};

using record_handle = std::shared_ptr<record_interface>;

}

#endif
