#ifndef GROUPCHAT_CORE_GROUPCHAT_HEADER
#define GROUPCHAT_CORE_GROUPCHAT_HEADER

#include "message.hpp"

#include <spsync/util/object_id.hpp>
#include <securepath/event_system/event_loop.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace securepath::groupchat {

/// Configuration for the group chat
struct groupchat_config {
	std::string server_address;
	std::uint16_t port;

	std::string db{"gc_client.db"};
	//identity et al
};

/// associate object id to a message
using message_id = sync::util::object_id;

/**
 * Simple group chat interface to send and receive messages using spsync as backend
 */
class groupchat {
public:
	groupchat(groupchat_config);
	~groupchat();

	/// Send a message to the chat
	message_id send_message(std::string const& message);
private:
	event_system::single_thread_event_loop loop_;

	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif