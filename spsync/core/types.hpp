#pragma once

#include "error.hpp"

#include <spsync/util/object_id.hpp>
#include <spsync/util/metadata.hpp>
#include <spsync/util/sequence_number.hpp>

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/types.hpp>
#include <securepath/util/octet_vector.hpp>

#include <chrono>
#include <cstdint>

namespace securepath::sync {

using time_point = serialisation::time_point;
using clock_type = serialisation::clock_type;
using record_tag = octet_vector;
using object_id = util::object_id;
using sequence_number = util::sequence_number;
using metadata = util::metadata;
using storage_id = octet_vector;

/// a time as the databases and the wire keep it
inline std::int64_t seconds_since_epoch(time_point t) {
	return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

}

