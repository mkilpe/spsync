#ifndef GROUPCHAT_CORE_TYPES_HEADER
#define GROUPCHAT_CORE_TYPES_HEADER

#include <spsync/core/users.hpp>
#include <spsync/util/object_id.hpp>

#include <securepath/serialisation/types.hpp>
#include <securepath/serialisation/sequence.hpp>

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

/// associate object id to a message
using message_id = sync::util::object_id;

using sync::users;

// key for the message metadata
std::string const groupchat_message_id{"gc_message_v1"};

// key for user change metadata
std::string const groupchat_name_id{"gc_name_v1"};

struct host_port {
	std::string host;
	std::uint16_t port;

	//auto operator<=>(host_port const&) const = default;
	//not working on android ndk 23 with clang

	bool operator<(host_port const& v) const {
		return host < v.host || (host == v.host && port < v.port);
	}
	bool operator==(host_port const& v) const {
		return host == v.host && port == v.port;
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & host & port;
	}
};

struct account_info {
	host_port server;
	std::string name;
	crypto::public_key_id key_id;
};

struct channel_id {
	server_id sid;
	chat_id cid;
};

}

#endif