#pragma once

#include "channel_list.hpp"
#include "types.hpp"

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
	std::string const path;
};

}