#pragma once

#include "types.hpp"

#include <spsync/client/record_util.hpp>
#include <spsync/util/sequence_number.hpp>

#include <string>

namespace securepath::groupchat {

enum class msg_state {
	pending,
	in_sync,
	/// accepted by a server but not yet durable (mirrors record_state::acked, plan D8)
	acked
};

struct message {
	std::string data;
	user_id sender_id;
	message_id mid;
	time_point sender_time;
	index_type index;
	msg_state state;
};

enum class msg_order {
	index_ascending,
	index_descending,
	/// order by the sender set message time; chunking with start_index stays index based,
	/// the time orders only honour max_count
	time_ascending,
	time_descending
};

struct message_search {
	int64_t start_index = 0; //0 means beginning for ascending and end for descending
	std::size_t max_count = 0;
	msg_order order{msg_order::index_descending};
	//t: add here what ever search criteria wanted
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

