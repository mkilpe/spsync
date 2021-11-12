#pragma once

#undef BOOST_CURRENT_LOCATION
#include <boost/json.hpp>

namespace securepath::sync::util::json {

using boost::json::value;
using boost::json::serialize;
using boost::json::parse;
using boost::json::value_to;
using boost::json::array;
using boost::json::object;

}
