#pragma once

#include "file.hpp"
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

/// a file shared with the chat (shared_files.txt): an own one when it is sent and when the
/// server confirmed it, another member's when its record arrives
struct on_file {
	typedef void type(server_chat_id, file_entry, file_change);
};

/// the transfer state of a file changed, or a transfer ended with the error (the state
/// stays what it was); gone with an error when the server refused the share for good
struct on_file_state {
	typedef void type(server_chat_id, file_id, file_state, error);
};

}
