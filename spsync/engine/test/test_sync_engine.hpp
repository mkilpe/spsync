#ifndef SPSYNC_ENGINE_TEST_TEST_SYNC_ENGINE_HEADER
#define SPSYNC_ENGINE_TEST_TEST_SYNC_ENGINE_HEADER

#include <spsync/core/progress.hpp>


namespace securepath::sync {

/**
 * The test implementation of the sync_engine to implement the engine_input
 */
class test_sync_engine : public sync_engine {
public:
	using sync_engine::sync_engine;

	virtual record_handle sync_object_change(object_id, metadata, record_data_handle) {

	}

	virtual record_handle sync_user_change(users user_change, metadata) {

	}

	virtual record_handle sync_segment_end(metadata) {

	}

};

}

#endif