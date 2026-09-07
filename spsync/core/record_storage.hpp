#pragma once

#include "record_interface.hpp"
#include <securepath/database/connection.hpp>

#include <deque>
#include <limits>
#include <memory>
#include <vector>

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

	/// find record that has the given operation id (see record_base::op_id)
	record_handle find_op_id(octet_vector const&) const;

	/// highest sequence number of record received from server with state in_sync or pending_sync
	sequence_number highest_sequence_number() const;

	/**
	 * Lowest sequence in [from, highest] without a record received from the server (states
	 * in_sync, acked, pending_sync); invalid when those are contiguous. Weak modes accept
	 * gapped records and a fetch interrupted by a lost connection or a replica hop leaves
	 * a gap behind that must still be filled (plan 4.5).
	 */
	sequence_number first_missing_sequence(sequence_number from = sequence_number{1}) const;

	/// highest in sync sequence of user change or segment records (used to replay server mode cursors)
	sequence_number last_special_sequence() const;

	/// highest in sync sequence of data change records that add an object (no previous record tag)
	sequence_number last_data_add_sequence() const;

	/// find the newest in sync record of the given type (e.g. the newest segment record)
	record_handle find_last_of_type(record_type_tag) const;

	/// all in sync records of the given type in sequence order (e.g. the user change
	/// records for the membership merge, plan 4.6)
	std::vector<record_handle> find_all_of_type(record_type_tag) const;

	/// tags of the in sync records with sequence in [first, last], in sequence order
	std::deque<record_tag> tags_in_range(sequence_number first, sequence_number last) const;

	/**
	 * The records in the given state with sequence in [first, last], in sequence order,
	 * at most max entries. Sequences without a record are skipped (a history cut leaves
	 * the retained records sparse below the anchor).
	 */
	std::vector<record_handle> find_range(sequence_number first, sequence_number last,
		record_state state = record_state::in_sync, std::size_t max = std::numeric_limits<std::size_t>::max()) const;

	/**
	 * Tags of the records below the given sequence that current objects still depend on:
	 * for every object id the newest in sync record and its previous-record chain
	 * (segments plan SEG 5/S6). This is the retained set of a history cut.
	 */
	std::vector<record_tag> object_chain_tags_below(sequence_number below) const;

	/**
	 * The stored assignment envelopes of the given origin server with origin sequence in
	 * [from, to], in origin sequence order, at most max entries (plan 4.4 anti-entropy).
	 */
	/// block id of the newest in sync record assigned by the given origin (invalid when none)
	chain_block_id last_of_origin(octet_vector const& origin) const;

	std::vector<octet_vector> find_origin_assignments(octet_vector const& origin,
		sequence_number from, sequence_number to, std::size_t max) const;

	/**
	 * The id of the server the sequence cursor belongs to (plan 4.5): the sequences of
	 * the in sync records are that server's assignments. Empty when never set; a client
	 * connecting to a different replica in weak mode resyncs and adopts its cursor.
	 */
	octet_vector cursor_owner() const;
	void set_cursor_owner(octet_vector const&);


	// -- truncation --

	/**
	 * Remove every in_sync / acked / pending_sync record with sequence >= first_removed,
	 * together with their object records, in one transaction. pending_commit records are
	 * never touched. With demote_acked set, acked records in the range are demoted back
	 * to pending_commit (keeping op id and content for rebase) instead of removed.
	 * Cached handles of removed records are set to record_state::invalid.
	 *
	 * Returns the removed blocks in ascending sequence order (demoted blocks excluded).
	 */
	std::vector<chain_block> truncate_from(sequence_number first_removed, bool demote_acked = false);

	/**
	 * The mirror of truncate_from for a history cut (segments plan SEG 5): remove every
	 * in_sync / acked / pending_sync record with sequence < first_kept, except the
	 * records with a retained tag, together with the object records of the removed ones,
	 * in one transaction. pending_commit records are never touched. Cached handles of
	 * removed records are set to record_state::invalid.
	 *
	 * Returns the removed blocks in ascending sequence order.
	 */
	std::vector<chain_block> truncate_prefix(sequence_number first_kept, std::vector<record_tag> const& retained);


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
	record_handle insert_to_db(chain_block const&, record_state, record_type_tag type, octet_vector const& op_id);
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

template<typename RecordType>
record_handle record_storage::create(auth_record<RecordType> const& rec) {
	return create(chain_block(rec, rec.record.last_seen_block().sequence + 1), record_state::pending_commit);
}

}

