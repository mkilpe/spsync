#pragma once

#include "message.hpp"
#include "channel.hpp"

#include <spsync/core/users.hpp>
#include <securepath/util/error.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <future>

namespace securepath::groupchat {

/**
 * Group chat connection to a single server
 */
class chat_connection {
public:
	chat_connection(chat_conn_context context);
	~chat_connection();

	/// connect to storage server
	std::future<void> connect();

	/// disconnect from server
	void disconnect();

	/// Create chat on given server, will call on_create when fail or succeed
	channel& create_chat(std::string name, users = {});

	/// join existing chat
	channel& join(sync::client::storage_info const& sinfo, std::string const& name);

	/// load existing storage, this makes the storage to synchronise
	channel& load(chat_id const& storage);

	/// get existing storage, otherwise throw exception
	channel& get(chat_id const& storage);

	/// get all ids of the channels in this connection
	std::deque<chat_id> channel_ids() const;

	/// Attached network context
	network::context& context();

	/// Host and port for this connection
	host_port end_point() const;

	/// Get the id of this chat connection
	server_id id() const;

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
