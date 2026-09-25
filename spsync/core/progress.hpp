// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/data/data_descriptor.hpp>

#include <securepath/event_system/event_handler.hpp>

namespace securepath::sync {

/// Events a progress handler may receive; one that does not care ignores them
namespace progress_events {

/**
 * Transfer progress of one record data (RD7): the encrypted octets known to be at the
 * other side so far, of the data's enc_size. A resumed transfer starts from what the
 * other side already had.
 */
struct on_data_progress {
	typedef void type(data_id, std::uint64_t transferred, std::uint64_t total, bool upload);
};

}

/**
 * Base interface for progress in the spsync system (eg. download/upload progress, record committing)
 *
 */
struct progress : event_system::event_handler {
	progress(event_system::event_loop& loop) : event_handler(loop) {}

	virtual ~progress() = default;
};

}

