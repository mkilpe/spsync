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

	/**
	 * Get the last block id in the chain in 'in sync' state if allow_local is false,
	 * otherwise also consider pending_commit state records
	 */
	chain_block_id last_block(bool allow_local = false) const;

	/**
	 * Find the last record in the chain in_sync if allow_local is false, otherwise also consider
	 * pending_commit state records
	 */
	record_handle find_last(bool allow_local = false) const;

	/// find the first record in the chain
	record_handle find_root() const;

	/// find record that has the given block hash
	record_handle find(octet_vector const&, record_state = record_state::in_sync) const;

	/// find record based on sequence number with specific state
	record_handle find(sequence_number, record_state = record_state::in_sync) const;

	/// find record that has the given tag
	record_handle find_tag(octet_vector const&) const;

	/// highest sequence number of record received from server with state in_sync or pending_sync
	sequence_number highest_sequence_number() const;

	/// highest in sync sequence of user change or segment records (used to replay server mode cursors)
	sequence_number last_special_sequence() const;

	/// highest in sync sequence of data change records that add an object (no previous record tag)
	sequence_number last_data_add_sequence() const;


	// -- pending commit --

	/// find the first record that is waiting to be committed
	record_handle find_first_pending_commit() const;

	/// find next pending commit after the given record (must be pending commit)
	record_handle find_next_pending_commit(record_handle) const;


	// -- per object operations --

	/// find the last record with given object id
	record_handle find_last(object_id const&) const;

	/// find the first record for given object id
	record_handle find_first(object_id const&) const;

	/// find by internal id
	record_handle find_internal(record_internal_id) const;


	/// create new record, the first function sets the state to be unknown and the object id is not set
	template<typename RecordType>
	record_handle create(auth_record<RecordType> const&);
	record_handle create(auth_record<data_change_record> const&);
	record_handle create(chain_block const&, record_state state);

private:
	template<typename RecordType>
	record_handle create_impl(RecordType const& r, chain_block const& rec, record_state state);
	record_handle insert_to_db(chain_block const&, record_state, record_type_tag type);
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

template<typename RecordType>
record_handle record_storage::create(auth_record<RecordType> const& rec) {
	return create(chain_block(rec, rec.record.last_seen_block().sequence + 1), record_state::pending_commit);
}

}

#endif
