#ifndef SPSYNC_CORE_TYPES_HEADER
#define SPSYNC_CORE_TYPES_HEADER

#include "error.hpp"

#include <spsync/util/object_id.hpp>
#include <spsync/util/metadata.hpp>
#include <spsync/util/sequence_number.hpp>

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/types.hpp>
#include <securepath/util/octet_vector.hpp>

#include <cstdint>

namespace securepath::sync {

using time_point = serialisation::time_point;
using clock_type = serialisation::clock_type;
using record_tag = octet_vector;
using object_id = util::object_id;
using sequence_number = util::sequence_number;
using metadata = util::metadata;

}

#endif