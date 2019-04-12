#ifndef GROUPCHAT_CORE_MESSAGE_HEADER
#define GROUPCHAT_CORE_MESSAGE_HEADER

#include <spsync/util/sequence_number.hpp>

#include <chrono>
#include <string>

namespace securepath::groupchat {

using time_point = std::chrono::time_point<std::chrono::system_clock>;

struct message {
	std::string data;
	std::string sender_nick;
	time_point time;
	sync::util::sequence_number seq;
};

}

#endif