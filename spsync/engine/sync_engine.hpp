#ifndef SPSYNC_ENGINE_SYNC_ENGINE_HEADER
#define SPSYNC_ENGINE_SYNC_ENGINE_HEADER

#include "interface.hpp"
#include <spsync/comm/interface.hpp>
#include <spsync/core/progress.hpp>

#include <memory>

namespace securepath::sync {

class encryption_key_storage;

/**
 * The configuration for the sync engine
 */
struct sync_engine_config {
	/// this is id for the repository, it is only used for logging to help trace/debug things if set
	std::string log_id;
};

/**
 * The engine to synchronise records and record data
 */
class sync_engine
	: public comm_output
	, public engine_input
{
public:
	sync_engine(comm_input&, encryption_key_storage&, sync_engine_config);
	~sync_engine();

	/// set the engine output interface that it uses to communicate with higher layer
	void set_output(engine_output*);

	/// re-set the engine configuration
	void set_config(sync_engine_config);

	// --- comm_output interface, see comm/interface.hpp ---
	virtual void on_record_response(request_handle, result<std::deque<serialised_record>> const&);
	virtual void on_data_response(request_handle, result<record_data_handle> const&);
	virtual void on_commit_response(request_handle, result<serialised_record> const&);
	virtual void on_data_uploaded(request_handle, std::optional<error>);
	virtual void on_record_received(serialised_record const&);

	// --- engine_input interface, see interface.hpp ---
	virtual record_handle sync_object_change(object_id, metadata, record_data_handle = {});
	virtual record_handle sync_user_change(users user_change, metadata = {});
	virtual record_handle sync_segment_end(metadata = {});
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif
