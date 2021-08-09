#pragma once

#include "cli_window.hpp"

#include <groupchat/core/groupchat.hpp>

namespace securepath::groupchat {

class gc : public groupchat {
public:
	gc(event_system::event_loop&, cli_window& win);

	/// called when server connected
	void on_connect(server_id) override;
	/// called when server disconnected
	void on_disconnect(server_id, error) override;
	/// called when chat created or creating failed
	void on_create(server_id, chat_id, error) override;
	/// called when user changed or failed
	void on_change_user(server_id, chat_id, sync::users change, error) override;
	/// called when chat joined or it failed
	void on_join(server_id, chat_id) override;
	/// called when chat message received
	void on_message(server_id, chat_id, message) override;

private:
	cli_window& win_;
};

}