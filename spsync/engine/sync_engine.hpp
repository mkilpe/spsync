#ifndef SPSYNC_ENGINE_SYNC_ENGINE_HEADER
#define SPSYNC_ENGINE_SYNC_ENGINE_HEADER

#include "interface.hpp"
#include <spsync/comm/interface.hpp>
#include <spsync/core/progress.hpp>

#include <memory>

namespace securepath::sync {

/**
 * The configuration for the sync engine
 */
struct sync_engine_config {

};

/**
 * The engine to synchronise records and record data
 */
class sync_engine
	: public comm_output
	, public engine_input
{
public:
	sync_engine(comm_input& comm, sync_engine_config);
	~sync_engine();

	void set_output(engine_output*);

	//--- comm_output interface


	//--- engine_input interface, see interface.hpp
	virtual record_handle sync_object_change(object_id const&, metadata const&, record_data_handle = {});
	virtual void sync_user_change(users const&, metadata const& = {});
	virtual void sync_segment_end(metadata const& = {});
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif
