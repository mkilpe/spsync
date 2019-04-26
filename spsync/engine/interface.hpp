#ifndef SPSYNC_ENGINE_INTERFACE_HEADER
#define SPSYNC_ENGINE_INTERFACE_HEADER

#include <spsync/core/record_data.hpp>
#include <spsync/core/record_storage.hpp>
#include <spsync/core/users.hpp>
#include <spsync/util/object_id.hpp>
#include <spsync/util/metadata.hpp>

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
	//q: what should the return type be there? somehow one needs to know when it was success full (ie. identify the record later on)

	/// synchronise user change
	virtual void sync_user_change(users const&, metadata const& = {}) = 0;

	/// synchronise segment end structure
	virtual void sync_segment_end(metadata const& = {}) = 0;
};


/**
 * The interface which synchroniser notifies the higher level of object change, user change or a like
 */
struct engine_output {
	virtual ~engine_output() = default;

	/**
	 * Called when server notifies about committed object data change.
	 * This is also called for object change records you did yourself.
	 */
	virtual void on_object_data_changed(record_handle) {}

	//conflicting object change ??

	/// Called when user change happened
	virtual void on_user_changed(users const&) {}

	//users changed
	//conflicting user change ??
};

}

#endif
