#pragma once

#include "data_descriptor.hpp"
#include "data_state_table.hpp"

#include <securepath/database/connection.hpp>

#include <cstdint>
#include <map>
#include <vector>

namespace securepath::sync {

/**
 * The record storage's index of record data (record_data.txt RD9): which record objects
 * name which row of the record data table (data_state_table). A change with a data
 * descriptor references the row of its data_id when its record is stored, records
 * naming the same data share the row, removing records drops their references - and
 * the reference counting answers what the storage owes, wants and may let go: the
 * data of confirmed records in a state, the data nothing names any more, the data
 * only superseded versions name. Queries over the record storage's tables (record,
 * record_objects) and the data table in the same database; walking the versions of an
 * object is the record storage's business.
 */
class data_index {
public:
	/// the tables exist: the record storage made them when it was opened
	explicit data_index(database::connection_ptr);

	/// the row of the data a record that is being stored names, made (deferred) when the
	/// data is new; a data the retention policy had let go is wanted again by its record
	std::uint64_t reference(data_descriptor const&);

	/// number of object records, of records in any state, that reference the row
	std::uint64_t reference_count(std::uint64_t data_ref) const;

	/**
	 * The data in the given state that a server confirmed record (in_sync, acked)
	 * references, ordered by the sequence of the first such record: with upload_pending
	 * the uploads still owed, in commit order (RD4/RD7).
	 */
	std::vector<data_id> confirmed_in_state(record_data_state) const;

	/// the data ids of the rows no object record references any more, one query
	std::vector<data_id> unreferenced() const;

	/// remove the rows of unreferenced() in one transaction and return their ids
	std::vector<data_id> remove_unreferenced();

	/// of the rows referenced as given (row -> references by superseded versions), those
	/// that nothing else names - a kept version, a record above a cut, a record not in
	/// sync yet - and that are not pruned yet
	std::vector<data_state_row> only_referenced_by(std::map<std::uint64_t, std::uint64_t> const& references) const;

	/// the rows marked pruned in one transaction; returns their ids
	std::vector<data_id> prune(std::vector<data_state_row> const&);

private:
	database::connection_ptr db_;
};

}
