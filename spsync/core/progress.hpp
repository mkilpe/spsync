#ifndef SPSYNC_CORE_PROGRESS_HEADER
#define SPSYNC_CORE_PROGRESS_HEADER

#include <securepath/event_system/event_handler.hpp>

namespace securepath::sync {

/**
 * Base interface for progress in the spsync system (eg. download/upload progress, record committing)
 *
 */
struct progress : event_system::event_handler {
    progress(event_system::event_loop&);

	virtual ~progress() = default;
};

}

#endif