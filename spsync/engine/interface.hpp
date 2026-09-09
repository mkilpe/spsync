#pragma once

#include <spsync/core/record_data.hpp>
#include <spsync/core/record_storage.hpp>
#include <spsync/core/users.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/util/object_id.hpp>
#include <spsync/util/metadata.hpp>

#include <securepath/event_system/event_handler.hpp>
#include <securepath/event_system/event_loop.hpp>

namespace securepath::sync {

using util::object_id;
using util::metadata;

/**
 * The interface to tell synchroniser about object change, user change or make segment
 * These calls will not block.
 */
struct engine_input {
	virtual ~engine_input() = default;

	/// synchronise object change with given id, user metadata and data
	virtual record_handle sync_object_change(object_id, metadata, record_data_handle = {}) = 0;

	/// synchronise user change
	virtual record_handle sync_user_change(plain_user_change_data, metadata = {}) = 0;

	/// synchronise segment end structure
	virtual record_handle sync_segment_end(metadata = {}) = 0;

	//todo: control interface to get data for object etc
};


/**
 * The interface which synchroniser notifies the higher level of object change, user change or a like
 */
struct engine_output : event_system::event_handler {

	engine_output(event_system::event_loop&);

	virtual ~engine_output() = default;

	/**
	 * Called when server notifies about committed object data change.
	 * This is also called for object change records you did yourself.
	 */
	virtual void on_object_data_changed(record_handle) {}

	//conflicting object change ??

	/// Called when user change happened
	virtual void on_user_changed(record_handle) {}

	/**
	 * Called when the server is suspected of showing two different histories (plan 2.6,
	 * strict mode): the incoming record's authenticated back reference names a block we
	 * hold in sync under a different hash for the same sequence. local is our record at
	 * that sequence, remote the incoming block whose last_seen_block disagrees. The
	 * engine stops committing to the storage (D10: detection halts, never heals); the
	 * application decides what to do - see doc/distributed_sync.txt phase 5.
	 */
	virtual void on_fork_suspected(record_handle local, chain_block remote) {}

	/**
	 * Called when an object changed underneath a pending record (per conflicting object).
	 * local is the own pending record, remote the newest record for the object. With
	 * conflict_policy::rebase_on_top the local record has been rebuilt on top of remote;
	 * with conflict_policy::ask it has been cancelled (state invalid).
	 */
	virtual void on_object_conflict(record_handle local, record_handle remote) {}

	/**
	 * Called when the server rejected a pending record for a reason no retry can lift
	 * (too big, invalid): the record was set invalid and will not be committed. The
	 * application decides what to tell the user. Transient rejections (a replica still
	 * syncing, an unknown signer) are not reported: the engine retries them itself.
	 */
	virtual void on_record_rejected(record_handle, error) {}

	//users changed
	//conflicting user change ??

	/// this converts events to above virtual calls
	void handle_event(std::unique_ptr<event_system::event_base> ev) override;
};

/// Events that map to the engine_output virtual functions
namespace engine_events {
struct on_object_data_changed {
	typedef void type(record_handle);
};
struct on_user_changed {
	typedef void type(record_handle);
};
struct on_object_conflict {
	typedef void type(record_handle, record_handle);
};
struct on_fork_suspected {
	typedef void type(record_handle, chain_block);
};
struct on_record_rejected {
	typedef void type(record_handle, error);
};
}

}

