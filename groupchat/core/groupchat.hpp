#ifndef GROUPCHAT_CORE_GROUPCHAT_HEADER
#define GROUPCHAT_CORE_GROUPCHAT_HEADER

#include "message.hpp"
#include "channel.hpp"
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
	std::string server_address;
	std::uint16_t port;

	std::string db{"gc_client.db"};
	//identity et al
};

/**
 * Simple group chat interface to send and receive messages using spsync as backend
 */
class groupchat {
public:
	groupchat(groupchat_config, event_system::event_loop&);
	~groupchat();

	/// connect to storage server
	server_id connect(std::string_view server, std::uint16_t port);

	/// disconnect from server
	void disconnect(server_id);

	/// Create chat on given server, will call on_create when fail or succeed
	chat_id create_chat(server_id);

	/// change users for chat
	void change_user(server_id const& server, chat_id const& storage, sync::users change);

	/// join existing chat
	void join(server_id const& server, chat_id const& storage);

	/// Send a message to the chat
	message_id send_message(server_id const& server, chat_id const& chat, std::string const& message);

public:
	/// called when server connected
	virtual void on_connect(server_id) = 0;
	/// called when server disconnected
	virtual void on_disconnect(server_id, error) = 0;
	/// called when chat created or creating failed
	virtual void on_create(server_id, chat_id, error) = 0;
	/// called when user changed or failed
	virtual void on_change_user(server_id, chat_id, sync::users change, error) = 0;
	/// called when chat joined or it failed
	virtual void on_join(server_id, chat_id) = 0;
	/// called when chat message received
	virtual void on_message(server_id, chat_id, message);
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif