#pragma once

#include <mutex>

namespace securepath::sync {

/**
 * this gives possibility to use different kind of threading strategy or debug mutex
 * -- the engine uses std::unique_lock to lock the mutex
 */
using engine_mutex_type = std::recursive_mutex;

}

