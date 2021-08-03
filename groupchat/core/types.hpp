#ifndef GROUPCHAT_CORE_TYPES_HEADER
#define GROUPCHAT_CORE_TYPES_HEADER

#include <spsync/util/object_id.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace securepath::groupchat {

/// handle for chat
using chat_id = octet_vector;

/// handle for server
using server_id = std::size_t;

// key for the message metadata
std::string const groupchat_message_id{"message_v1"};

}

#endif