#pragma once

#include "channel_list.hpp"
#include "types.hpp"
#include <spsync/util/config.hpp>

#include <securepath/event_system/event_handler.hpp>
#include <securepath/network/encryption/context.hpp>

namespace securepath::groupchat {

// some context information for chat_connection and channel
struct chat_conn_context {
	server_id const sid;
	host_port const key_server;
	host_port const sync_server;
	event_system::event_handler& callback;
	network::context& context;
	channel_list& channels;
	sync::util::config& config;
	std::string const path;
	/// further replicas of the sync server, tried in order after the primary (plan 4.5)
	std::vector<host_port> const fallback_sync_servers{};
};

}