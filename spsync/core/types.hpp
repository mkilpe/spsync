#ifndef SPSYNC_CORE_TYPES_HEADER
#define SPSYNC_CORE_TYPES_HEADER

#include <spsync/util/sequence_number.hpp>

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/types.hpp>
#include <securepath/util/octet_vector.hpp>

#include <cstdint>

namespace securepath::sync {

using time_point = serialisation::time_point;

}

#endif