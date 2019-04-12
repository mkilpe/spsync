#ifndef GROUPCHAT_CORE_GROUPCHAT_HEADER
#define GROUPCHAT_CORE_GROUPCHAT_HEADER

#include "message.hpp"

#include <spsync/util/object_id.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace securepath::groupchat {

/// Configuration for the group chat
struct groupchat_config {
	std::string server_address;
	std::uint16_t port;
	//identity et al
};

/// assosiate object id to a message
using message_id = sync::util::object_id;

/**
 * Simple group chat interface to send and receive messages
 */
class groupchat {
public:
	groupchat(groupchat_config);
	~groupchat();

	/// Send a message to the chat
	message_id send_message(std::string const& message);
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif