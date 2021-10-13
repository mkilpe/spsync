#pragma once

#include "message.hpp"

namespace securepath::groupchat {

struct msg_change {
	index_type new_index;
	index_type old_index;
	message_id id;
	msg_state state;
};

/**
 *
 */
class message_storage {
public:
	message_storage(database::connection_ptr);

	/// insert message, if the message is pending, change it to in_sync state
	msg_change insert(message_id const&, message_data const&, msg_state state);

	std::deque<message> get(message_search) const;
private:
	std::int64_t update_pending(message_id const& id);
	void get_in_sync(message_search, std::deque<message>&) const;
	void get_pending(message_search, std::deque<message>&) const;

private:
	mutable std::mutex mutex_;
	database::connection_ptr db_;
	std::int64_t sync_max_index_{};
};

}
