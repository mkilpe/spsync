#pragma once

#include "message.hpp"

#include <spsync/client/record_data.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/record_storage.hpp>

#include <securepath/database/connection.hpp>

#include <deque>
#include <functional>
#include <optional>
#include <string>

namespace securepath::groupchat {

/// one object of a store: its id and payload, its place in the list, pending or confirmed
struct stored_object {
	sync::util::object_id id;
	octet_vector payload;
	time_point sender_time;
	index_type index{};
	bool pending{};
};

/// where an insert put the object, and where it was while pending (0 when it was not)
struct object_change {
	index_type new_index{};
	index_type old_index{};
};

/**
 * The two-table store messages and files share: objects the server confirmed, in the
 * order they arrived under an index that never changes, and own objects still pending
 * after them, under indexes above the confirmed ones that shift down as they confirm.
 * A search is by index in either direction with chunking, or by the sender time.
 * Not thread-safe.
 */
class object_store {
public:
	/// the confirmed and the pending table; both are created when missing
	object_store(database::connection_ptr, std::string table, std::string pending_table);

	/**
	 * Insert an object: a pending one at the end of the pending list (an object still
	 * pending at a restart keeps its entry), a confirmed one at the end of the confirmed
	 * list, leaving the pending list when it was there.
	 */
	object_change insert(sync::util::object_id const&, octet_vector const& payload, time_point sender_time
		, sync::sequence_number seq, sync::record_internal_id iid, bool pending);

	/// the objects a search names, in its order
	std::deque<stored_object> get(message_search) const;

	/// the object by id, from either table
	std::optional<stored_object> find(sync::util::object_id const&) const;

	/// the newest confirmed record sequence held: where a reconciliation with the records starts
	sync::sequence_number latest_sequence() const;

	/// drop a pending object; false when it was not pending
	bool remove_pending(sync::util::object_id const&);

private:
	std::int64_t update_pending(sync::util::object_id const& id);
	std::string prepare_string(std::string const& table, message_search const&) const;
	void get_confirmed(message_search, std::deque<stored_object>&) const;
	void get_pending(message_search, std::deque<stored_object>&) const;
	std::deque<stored_object> get_by_time(message_search) const;

private:
	database::connection_ptr db_;
	std::string const table_;
	std::string const pending_table_;
	std::int64_t sync_max_index_{};
};

/**
 * The data changes of the records after the given sequence, then of the own records
 * still pending (pending = true): what a store reconciles itself with at start-up.
 * Records that cannot be read (no key yet) are skipped.
 */
void walk_data_changes(sync::record_storage const&, sync::encryption_key_storage const&, sync::sequence_number after
	, std::function<void(std::deque<sync::single_data_change> const&, bool pending)> const&);

}
