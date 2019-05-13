#ifndef SPSYNC_ENGINE_TYPES_HEADER
#define SPSYNC_ENGINE_TYPES_HEADER

#include <mutex>

namespace securepath::sync {

/**
 * this gives possibility to use different kind of threading strategy or debug mutex
 * -- the engine uses std::unique_lock to lock the mutex
 */
using engine_mutex_type = std::mutex;

}

#endif
