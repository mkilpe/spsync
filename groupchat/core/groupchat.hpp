#pragma once

#include "message.hpp"
#include "channel.hpp"
#include "chat_connection.hpp"
#include "contact_list.hpp"
#include "types.hpp"

#include <spsync/core/users.hpp>
#include <spsync/util/object_id.hpp>
#include <securepath/event_system/event_loop.hpp>
#include <securepath/util/error.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace securepath::groupchat {
namespace gc = groupchat;

/// Configuration for the group chat
struct groupchat_config {
	std::string db{"gc_client.db"};
};

struct account_info {
	host_port server;
	std::string name;
	crypto::public_key_id key_id;
};

/**
 * Simple group chat interface to send and receive messages using spsync as backend
 */
class groupchat {
public:
	groupchat(event_system::event_handler& callback, groupchat_config);
	groupchat(event_system::event_handler& callback, network::context& context, groupchat_config);
	~groupchat();

	/// Returns associated account information if account exists
	std::optional<gc::account_info> account_info() const;

	/// Try to create account (create key, register key to the server)
	void create_account(host_port const& server, std::string const& name);

	/// Load and connect to existing channels
	std::deque<server_id> load_channels();

	/// create/get chat connection to given server
	std::shared_ptr<chat_connection> load(host_port const& server);
	std::shared_ptr<chat_connection> find(server_id) const;

	/// return contacts
	contact_list& contacts();

	/// Attached network context
	network::context& context();

private:
	bool check_account_exists(groupchat_config const&) const;

private:
	groupchat_config config_;
	event_system::event_handler& callback_;
	network::context* context_{};

	class impl;
	std::unique_ptr<impl> impl_;

};

}
