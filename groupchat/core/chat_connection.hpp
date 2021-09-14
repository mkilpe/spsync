#pragma once

#include "message.hpp"
#include "channel.hpp"
#include "channel_list.hpp"
#include "types.hpp"

#include <spsync/core/users.hpp>
#include <spsync/util/object_id.hpp>
#include <securepath/event_system/event_loop.hpp>
#include <securepath/util/error.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace securepath::groupchat {

/**
 * Group chat connection to a single server
 */
class chat_connection {
public:
	chat_connection(server_id, host_port, event_system::event_handler& callback, network::context& context, channel_list&);
	~chat_connection();

	/// connect to storage server
	void connect();

	/// disconnect from server
	void disconnect();

	/// Create chat on given server, will call on_create when fail or succeed
	channel& create_chat(std::string name);

	/// join existing chat
	channel& join(chat_id const& storage);

	/// get existing storage, otherwise throw exception
	channel& get(chat_id const& storage);

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
