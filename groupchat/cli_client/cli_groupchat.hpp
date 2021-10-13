#pragma once

#include "cli_window.hpp"

#include <groupchat/core/groupchat.hpp>

namespace securepath::groupchat {

class cli_groupchat : public event_system::event_handler, public groupchat {
public:
	cli_groupchat(event_system::event_loop&, cli_window& win);
	~cli_groupchat();

	/// called when server connected
	void on_connect(server_id);
	/// called when server disconnected
	void on_disconnect(server_id, error);
	/// called when chat created or creating failed
	void on_create(server_id, chat_id, error);
	/// called when user changed or failed
	void on_change_user(server_id, chat_id, sync::users change, error);
	/// called when chat joined or it failed
	void on_join(server_id, chat_id, error);
	/// called when chat message received
	void on_message(server_id, chat_id, message_data, msg_change);

	void handle_event(std::unique_ptr<event_system::event_base> ev) override;

private:
	cli_window& win_;
	std::map<chat_id, int> channel_map_;
};

}