#ifndef SPSYNC_ENGINE_SYNC_ENGINE_HEADER
#define SPSYNC_ENGINE_SYNC_ENGINE_HEADER

#include "interface.hpp"
#include <spsync/comm/interface.hpp>
#include <spsync/core/progress.hpp>

#include <memory>

namespace securepath::sync {

class sync_engine
	: public comm_output
	, public engine_input
{
public:
	sync_engine(comm_input&);
	~sync_engine();

	void set_output(engine_output*);

	//--- comm_output interface


	//--- engine_input interface

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif
