#pragma once

#include "sync_engine_config.hpp"

#include <spsync/util/result.hpp>

#include <cstddef>

namespace securepath::sync {

class record_storage;
class encryption_key_storage;

/// What verify_history checked; the counters sum to the chain length
struct history_verify_report {
	/// non-segment records that were cryptographically verified (hash + authenticity)
	std::size_t verified_records{};
	/// segment records that were cryptographically verified
	std::size_t verified_segments{};
	/// records vouched only by an authenticated segment tag list
	std::size_t covered_records{};
};

/**
 * Verify the stored in sync history (segments plan SEG 4/S4).
 *
 * full walks every record: recomputed hash, parent link and record authenticity.
 * fast verifies the chain from the newest segment's stated end onwards the same way,
 * then walks the segment backbone: every segment is authenticated and its tag list must
 * match the stored records of its range exactly. Covered records are vouched by the
 * lists without per-record crypto - their content is still authenticated when read.
 * Without any segment fast equals full. The crypto cost of fast is O(records past the
 * newest segment + number of segments) instead of O(chain length).
 */
util::result<history_verify_report> verify_history(record_storage const&, encryption_key_storage const&,
	history_verification);

}
