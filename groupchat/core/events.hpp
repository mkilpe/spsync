#pragma once

#include "message_storage.hpp"
#include "types.hpp"

namespace securepath::groupchat::events {

struct on_connect {
	typedef void type(server_id);
};

struct on_disconnect {
	typedef void type(server_id, error);
};

struct on_init {
	typedef void type(server_chat_id, error);
};

struct on_create {
	typedef void type(server_chat_id, sync::users, error);
};

struct on_change_user {
	typedef void type(server_chat_id, sync::users, error);
};

struct on_join {
	typedef void type(server_chat_id, sync::users, error);
};

struct on_message {
	typedef void type(server_chat_id, msg_data, msg_change);
};

/// a pending message the server refused for good; it was removed from the pending list
struct on_message_failed {
	typedef void type(server_chat_id, message_id, error);
};

}
