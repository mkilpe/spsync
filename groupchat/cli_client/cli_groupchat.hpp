#pragma once

#include "cli_window.hpp"

#include <flat_map>
#include "gc_cli_config.hpp"

#include <groupchat/core/groupchat.hpp>

#include <functional>
#include <vector>

namespace securepath::groupchat {

class cli_groupchat : public event_system::event_handler, public groupchat {
public:
	cli_groupchat(event_system::event_loop&, cli_window& win, gc_cli_config config);
	~cli_groupchat();

	std::optional<int> map_to_channel(chat_id const&) const;
	std::optional<chat_id> map_to_cid(int) const;
	/// the window channel of the chat, created with the given name when new
	int add_channel(chat_id const&, std::string const& name);
	void remove_channel(int);

	/// called when packet server connected
	void on_connect();
	/// called when packet server disconnected
	void on_disconnect(error);
	/// called when a sync server connection is up / lost (the replica in use is reported)
	void on_server_connect(server_id);
	void on_server_disconnect(server_id, error);
	/// called when chat created or creating failed
	void on_init(server_chat_id, error);
	/// called when user changed or failed
	void on_change_user(server_chat_id, sync::users change, error);
	/// called when chat joined or it failed
	void on_join(server_chat_id, sync::users change, error);
	/// called when chat message received
	void on_message(server_chat_id, msg_data, msg_change);
	/// called when the server refused a pending message for good
	void on_message_failed(server_chat_id, message_id, error);
	/// called when a file was shared with a chat (shared_files.txt)
	void on_file(server_chat_id, file_entry, file_change);
	/// called when the transfer state of a shared file changed
	void on_file_state(server_chat_id, file_id, file_state, error);

	void on_contacting(sync::client::request const& req
		, std::string const& name
		, std::string const& message);

	void handle_event(std::unique_ptr<event_system::event_base> ev) override;

private:
	int notice_channel(chat_id const&) const;
	std::string time_to_string(time_point) const;

private:
	cli_window& win_;
	gc_cli_config config_;
	std::flat_map<chat_id, int> channel_map_;
	std::flat_map<int, chat_id> cid_map_;
};

}