#pragma once

#include <spsync/engine/sync_engine.hpp>

namespace securepath::sync::test {

/**
 * The test implementation of the sync_engine to implement the engine_input
 */
class test_sync_engine : public sync_engine {
public:
	using sync_engine::sync_engine;

	~test_sync_engine() { stop_handler(); }

};

}

