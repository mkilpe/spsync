#ifndef GROUPCHAT_CORE_MESSAGE_HEADER
#define GROUPCHAT_CORE_MESSAGE_HEADER

#include "types.hpp"

#include <spsync/client/record_util.hpp>
#include <spsync/util/sequence_number.hpp>

#include <chrono>
#include <string>

namespace securepath::groupchat {

using clock_type = std::chrono::system_clock;
using time_point = std::chrono::time_point<clock_type>;

struct message {
	std::string data;
	user_id sender_id;
	message_id mid;
	time_point time;
	sync::util::sequence_number seq;
};

struct message_search {
	std::size_t max_count = 0;
	sync::record_order order{sync::record_order::seq_descending};
	//t: add here what ever search criteria wanted
};

struct message_data {
	std::string message;
	time_point sender_time;

	user_id sender; //t: this is hack, need to implement signing of records

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & message & sender_time & sender;
	}
};

}

#endif