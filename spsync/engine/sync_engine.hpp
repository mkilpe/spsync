#ifndef SPSYNC_ENGINE_SYNC_ENGINE_HEADER
#define SPSYNC_ENGINE_SYNC_ENGINE_HEADER

#include <memory>

namespace securepath::sync {

class sync_engine {
public:
	sync_engine();
	~sync_engine();


private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif
