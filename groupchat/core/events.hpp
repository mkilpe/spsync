#pragma once

namespace securepath::groupchat::events {

struct on_connect {
	typedef void type(server_id);
};

struct on_disconnect {
	typedef void type(server_id, error);
};

struct on_create {
	typedef void type(server_id, chat_id, error);
};

struct on_change_user {
	typedef void type(server_id, chat_id, sync::users, error);
};

struct on_join {
	typedef void type(server_id, chat_id, error);
};

struct on_message {
	typedef void type(server_id, chat_id, message_data, msg_change);
};

}
