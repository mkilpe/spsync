#pragma once

#include <spsync/core/users.hpp>
#include <spsync/util/object_id.hpp>

#include <securepath/serialisation/types.hpp>
#include <securepath/serialisation/sequence.hpp>

#include <chrono>

namespace securepath::sync::client {

using clock_type = std::chrono::system_clock;
using time_point = std::chrono::time_point<clock_type>;

/// id for user/member/contact
using user_id = sync::util::user_id;
using user = sync::util::user;

std::string const contact_tag{"contacting_v1"};

using request_id = std::int64_t;

struct account_info {
	user me;
	std::string name;
	host_port server; //home sync server
	host_port packet_server;
};

}
