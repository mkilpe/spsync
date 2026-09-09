#pragma once

#include "message.hpp"
#include "channel.hpp"

#include <spsync/core/users.hpp>
#include <securepath/util/error.hpp>
#include <securepath/util/task.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <functional>
#include <future>

namespace securepath::groupchat {

/**
 * Group chat connection to a single server
 */
class chat_connection {
public:
	chat_connection(chat_conn_context context);
	~chat_connection();

	/**
	 * Connect to the storage server; the replicas are tried in rotation (plan 4.5): after a
	 * failed or lost session the next attempt goes to the next endpoint, and a lost session
	 * reconnects by itself with a growing delay until disconnect() is called. The future is
	 * ready once connected (or holds the error); a call while an attempt is in flight
	 * returns that attempt's future, a call while connected a ready one
	 */
	std::shared_future<void> connect();

	/// disconnect from server and stop reconnecting
	void disconnect();

	/// true while the session with the sync server is up
	bool is_connected() const;

	/**
	 * Run the action once the session is up: right away when it is, otherwise from the
	 * connect that succeeds next (the automatic reconnect keeps trying); disconnect()
	 * fails the waiting actions with the error. Called on the event loop thread.
	 */
	void when_connected(std::move_only_function<void(error const&)>);

	/// the awaitable form of when_connected: completes on the loop thread when the
	/// session is up, throws the error when the connection was stopped
	securepath::task<void> connected();

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

	/// Host and port for this connection (the primary endpoint the chats are recorded under)
	host_port end_point() const;

	/// the replica the latest connection attempt went to (the primary or one of the fallbacks)
	host_port current_endpoint() const;

	/// Get the id of this chat connection
	server_id id() const;

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
