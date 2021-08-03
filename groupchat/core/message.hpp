#ifndef GROUPCHAT_CORE_MESSAGE_HEADER
#define GROUPCHAT_CORE_MESSAGE_HEADER

#include <spsync/util/sequence_number.hpp>
#include <securepath/serialisation/types.hpp>
#include <securepath/serialisation/sequence.hpp>

#include <chrono>
#include <string>

namespace securepath::groupchat {

using clock_type = std::chrono::system_clock;
using time_point = std::chrono::time_point<clock_type>;

struct message {
	std::string data;
	std::string sender_nick;
	time_point time;
	sync::util::sequence_number seq;
};

struct message_data {
	std::string message;
	time_point sender_time;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & message & sender_time;
	}
};

}

#endif