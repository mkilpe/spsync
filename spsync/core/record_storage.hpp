#ifndef SPSYNC_CORE_RECORD_STORAGE_HEADER
#define SPSYNC_CORE_RECORD_STORAGE_HEADER

#include "record_interface.hpp"
#include <securepath/database/connection.hpp>

#include <memory>

namespace securepath::sync {

/**
 * Keeps records and their current state which is used by the comm layer and the synchroniser
 *
 * The functions returning record_handle will cache the record_handle, this means that
 *  subsequent calls will return the same handle
 *
 * This interface is thread safe
 */
class record_storage {
public:
	/// construct with database connection
	record_storage(database::connection_ptr);
	~record_storage();


	// -- overall record chain --

	/// get the last block id in the chain received from server
	chain_block_id last_block() const;

	/// find the last record in the chain
	record_handle find_last() const;

	/// find the first record in the chain
	record_handle find_root() const;

	/// find record that has the given block hash
	record_handle find(octet_vector const&) const;

	/// find record that has the given tag
	record_handle find_tag(octet_vector const&) const;

	// -- per object operations --

	/// find the last record with given object id
	record_handle find_last(object_id const&) const;

	/// find the first record for given object id
	record_handle find_first(object_id const&) const;


	/// create new record, the first function sets the state to be unknown and the object id is not set
	template<typename RecordType>
	record_handle create(auth_record<RecordType> const&);
	record_handle create(auth_record<data_change_record> const&);
	record_handle create(chain_block const&, record_state state);

private:
	void create_object_records(octet_vector const& tag, data_change_record const& rec);
	record_handle create_impl(chain_block const& rec, record_state state);

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

template<typename RecordType>
record_handle record_storage::create(auth_record<RecordType> const& rec) {
	return create(chain_block(rec), record_state::unknown);
}

}

#endif
