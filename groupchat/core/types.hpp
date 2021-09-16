#ifndef GROUPCHAT_CORE_TYPES_HEADER
#define GROUPCHAT_CORE_TYPES_HEADER

#include <spsync/util/object_id.hpp>

#include <securepath/serialisation/types.hpp>
#include <securepath/serialisation/sequence.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace securepath::groupchat {

/// handle for chat
using chat_id = octet_vector;

/// handle for server
using server_id = std::size_t;

// key for the message metadata
std::string const groupchat_message_id{"gc_message_v1"};

// key for user change metadata
std::string const groupchat_name_id{"gc_name_v1"};

struct host_port {
	std::string host;
	std::uint16_t port;

	//auto operator<=>(host_port const&) const = default;
	//not working on ndk 23 with clang

	bool operator<(host_port const& v) const {
		return host < v.host || (host == v.host && port < v.port);
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & host & port;
	}
};

}

#endif