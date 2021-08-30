#pragma once

#include "message.hpp"
#include "channel.hpp"
#include "chat_connection.hpp"
#include "types.hpp"

#include <spsync/core/users.hpp>
#include <spsync/util/object_id.hpp>
#include <securepath/event_system/event_loop.hpp>
#include <securepath/util/error.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace securepath::groupchat {

/// Configuration for the group chat
struct groupchat_config {
	std::string db{"gc_client.db"};
	//identity et al
};

/**
 * Simple group chat interface to send and receive messages using spsync as backend
 */
class groupchat {
public:
	groupchat(event_system::event_handler& callback, groupchat_config);
	groupchat(event_system::event_handler& callback, network::context& context, groupchat_config);
	~groupchat();

	std::shared_ptr<chat_connection> load(std::string const& host, std::uint16_t port);
	std::shared_ptr<chat_connection> find(server_id) const;

	/// Attached network context
	network::context& context();

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
