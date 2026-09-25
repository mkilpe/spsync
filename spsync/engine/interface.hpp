#pragma once

#include <spsync/core/record_data.hpp>
#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/core/record_storage.hpp>
#include <spsync/core/users.hpp>
#include <spsync/core/records/equivocation_proof.hpp>
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

	/**
	 * Synchronise object change with given id, user metadata and data. The data handle
	 * is a source (e.g. memory_record_data, file_record_data): it is streamed once into
	 * the storage's data store, encrypted, before the record is created (RD7), so for a
	 * big source this call takes the time of reading and encrypting it - call it from a
	 * thread that may wait. The record commits without waiting for the upload; the data
	 * is upload_pending until on_data_state_changed says otherwise.
	 */
	virtual record_handle sync_object_change(object_id, metadata, record_data_handle = {}) = 0;

	/**
	 * The record data of a change of a data change record, read through the storage's
	 * data store; null when the change carries no data, the record cannot be read (no
	 * key) or the storage keeps no record data. The handle tells what is held locally
	 * (state, available_size).
	 */
	virtual record_data_handle object_data(record_handle, std::size_t change = 0) = 0;

	/**
	 * The same, and the data is fetched when it is not held (RD6: lazy by default, this
	 * is the asking): deferred, removed or remote_not_complete becomes download_pending
	 * and the download runs in the background - on_data_state_changed tells when it is
	 * in_sync, or remote_not_complete when the holders have only a part yet (the engine
	 * fetches the rest when the server tells it is there). A data whose content is held
	 * already under another data id is made locally instead of downloaded.
	 */
	virtual record_data_handle fetch_object_data(record_handle, std::size_t change = 0) = 0;

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
	 * Called when the server showed proof that an origin server assigned one sequence
	 * of the storage to two records (plan 5.4), verified with the origin's key. The
	 * server refuses that origin's records from then on. In strict mode the engine
	 * stops committing to the storage, as with a fork suspicion; in weak modes it goes
	 * on and the application decides what to make of it.
	 */
	virtual void on_equivocation(equivocation_proof const&) {}

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

	/**
	 * Called when the local state of a record data changed (RD7), e.g. to in_sync when
	 * the upload of an own data completed. The data is named by its data_id: every
	 * record whose descriptor has this manifest_digest shares it.
	 */
	virtual void on_data_state_changed(data_id, record_data_state) {}

	/**
	 * Called when the transfer of a record data ended with an error (refused by the
	 * server, quota, no data server). The state stays as it was (upload_pending,
	 * download_pending - what was received is kept); the engine tries again after the
	 * next connect, a download also when it is asked for again. A download that fails
	 * with unknown_data goes back to deferred: the server cut the record away (RD9).
	 * With data_pruned the transfer is over for good: the server let the data of this
	 * superseded version go under the storage's retention policy, the state is pruned
	 * and chunks held for an upload are dropped.
	 */
	virtual void on_data_transfer_failed(data_id, error) {}

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
struct on_equivocation {
	typedef void type(equivocation_proof);
};
struct on_record_rejected {
	typedef void type(record_handle, error);
};
struct on_data_state_changed {
	typedef void type(data_id, record_data_state);
};
struct on_data_transfer_failed {
	typedef void type(data_id, error);
};
}

}

