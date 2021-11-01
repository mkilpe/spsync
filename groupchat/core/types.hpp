#ifndef GROUPCHAT_CORE_TYPES_HEADER
#define GROUPCHAT_CORE_TYPES_HEADER

#include <spsync/core/users.hpp>
#include <spsync/util/object_id.hpp>

#include <securepath/serialisation/types.hpp>
#include <securepath/serialisation/sequence.hpp>

#include <infrastructure/packet_transport/server/server_lib/packet_server.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <tuple>

namespace securepath::groupchat {

using clock_type = std::chrono::system_clock;
using time_point = std::chrono::time_point<clock_type>;

/// index for messages
using index_type = std::int64_t;

/// handle for chat
using chat_id = octet_vector;

/// handle for server
using server_id = std::size_t;

/// id for user/member/contact
using user_id = sync::util::user_id;

/// user (id+keyserver)
using user = sync::util::user;

/// associate object id to a message
using message_id = sync::util::object_id;

using sync::users;

// key for the message metadata
std::string const groupchat_message_id{"gc_message_v1"};

// key for user change metadata
std::string const groupchat_name_id{"gc_name_v1"};

// tag used for contacting packets
std::string const groupchat_contacting_tag{"gc_contacting_v1"};

struct account_info {
	user me;
	std::string name;
	host_port server; //home sync server
	host_port packet_server;
};

struct channel_id {
	server_id sid;
	chat_id cid;
};

struct gc_contacting_data {
	std::string name;
	std::string message;
	serialisation::trailing_data trailing;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & name & message & trailing;
	}
};

struct gc_servers {
	std::string host;
	std::uint16_t key_server_port;
	std::uint16_t sync_server_port;
	std::uint16_t packet_server_port;

	host_port key_server() const { return host_port{host, key_server_port}; }
	host_port sync_server() const { return host_port{host, sync_server_port}; }
	host_port packet_server() const { return host_port{host, packet_server_port}; }
};

}

#endif