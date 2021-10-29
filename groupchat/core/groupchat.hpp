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
	std::string path;

	std::string db() const { return path.empty() ? "gc_client.db" : path + "/gc_client.db"; };
};

/**
 * Simple group chat interface to send and receive messages using spsync as backend
 */
class groupchat {
public:
	groupchat(event_system::event_handler& callback, groupchat_config);
	groupchat(event_system::event_handler& callback, network::context& context, groupchat_config);
	~groupchat();

	/// connect all existing chat connections and packet server connection
	void connect();

	/// disconnect
	void disconnect();

	/// Returns associated account information if account exists
	std::optional<gc::account_info> account_info() const;

	/// Try to create account (create key, register key to the server)
	void create_account(host_port const& server, std::string const& name);

	/// Load and connect to existing channels
	std::deque<channel_id> load_channels();

	/// create/get chat connection to given server
	std::shared_ptr<chat_connection> load(host_port const& server);
	std::shared_ptr<chat_connection> find(server_id) const;
	std::vector<std::shared_ptr<chat_connection>> connections() const;

	/// add contact to contact_list and send contacting packet
	void add_contact(crypto::public_key_id const& id, std::string const& name, host_port const& server);

	/// return contacts
	contact_list& contacts();

	/// return stored channel ids
	channel_list& channel_ids();

	/// Attached network context
	network::context& context();

private:
	bool check_account_exists(groupchat_config const&) const;

private:
	groupchat_config const config_;
	event_system::event_handler& callback_;
	network::context* const context_{};

	class impl;
	std::unique_ptr<impl> impl_;

};

}
