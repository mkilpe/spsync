#ifndef SPSYNC_TEST_TEST_PROGRESS_HEADER
#define SPSYNC_TEST_TEST_PROGRESS_HEADER

#include <spsync/core/progress.hpp>
#include <securepath/event_system/event_loop.hpp>

namespace securepath::sync::test {

/**
 * The test implementation of progress interface for unit tests
 */
class test_progress : public event_system::single_thread_event_loop, public progress {
public:
    test_progress() : progress(static_cast<event_system::event_loop&>(*this)) {}

    void handle_event(std::unique_ptr<event_system::event_base>) override {}
};

}

#endif