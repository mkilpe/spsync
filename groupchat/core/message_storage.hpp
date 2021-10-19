#pragma once

#include "message.hpp"
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/record_storage.hpp>

namespace securepath::groupchat {

struct msg_change {
	index_type new_index;
	index_type old_index;
	message_id id;
	msg_state state;
};

struct msg_data {
	msg_data() = default;

	msg_data(message_data const& d, user_id sender, sync::record_internal_id iid, sync::sequence_number seq = {})
	: message(d.message)
	, sender(std::move(sender))
	, sender_time(d.sender_time)
	, receiver_time(clock_type::now())
	, iid(iid)
	, seq(seq)
	{}

	std::string message;
	user_id sender;
	time_point sender_time;
	time_point receiver_time;
	time_point server_time;
	sync::record_internal_id iid;
	sync::sequence_number seq;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> s(ar);
		s & message & sender & sender_time & receiver_time & server_time & iid & seq;
	}
};

/**
 * Class to store and fetch message for single channel
 * Not thread-safe!
 */
class message_storage {
public:
	message_storage(database::connection_ptr);

	/// insert message, if the message is pending, change it to in_sync state
	msg_change insert(message_id const&, msg_data const&, msg_state state);

	/// get messages based on the search criteria (order, chunking, etc)
	std::deque<message> get(message_search) const;

	/// get latest in sync sequence, this is used on start-up to make sure we are in sync with records
	sync::sequence_number latest_sequence() const;
private:
	std::int64_t update_pending(message_id const& id);
	void get_in_sync(message_search, std::deque<message>&) const;
	void get_pending(message_search, std::deque<message>&) const;

private:
	database::connection_ptr db_;
	std::int64_t sync_max_index_{};
};

void sync_message_storage(message_storage&, sync::record_storage const&, sync::encryption_key_storage const&);

}
