#pragma once

#include "types.hpp"
#include <securepath/database/connection.hpp>
#include <deque>

namespace securepath::groupchat {

struct channel_data {
	host_port server;
	chat_id cid;
};

/**
 * Simple interface to keep track of existing chat channels
 */
class channel_list {
public:
	channel_list(database::connection_ptr);

	void add(chat_id const&, host_port const& server);
	std::deque<channel_data> enumerate(std::optional<host_port> = std::nullopt) const;
private:
	database::connection_ptr db_;
};

}
