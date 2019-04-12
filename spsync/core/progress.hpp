#ifndef SPSYNC_CORE_PROGRESS_HEADER
#define SPSYNC_CORE_PROGRESS_HEADER

namespace securepath::sync {

/**
 * Base interface for progress in the spsync system (eg. download/upload progress, record committing)
 *
 */
struct progress {
	virtual ~progress() = default;
};

}

#endif