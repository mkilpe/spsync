#pragma once

#include "types.hpp"
#include <securepath/database/connection.hpp>
#include <deque>

namespace securepath::groupchat {

struct channel_data {
	host_port server;
	chat_id cid;
};

//t: save server_id to database and use it instead of host_port to identify servers

/**
 * Simple interface to keep track of existing chat channels
 */
class channel_list {
public:
	channel_list(database::connection_ptr);

	/// Add channel id with its server to the storage
	void add(chat_id const&, host_port const& server);

	/// List all stored channels (only for specific server if given)
	std::deque<channel_data> enumerate(std::optional<host_port> = std::nullopt) const;

	/// Find the server for existing channel
	std::optional<host_port> find_server(chat_id const&) const;
private:
	database::connection_ptr db_;
};

}
