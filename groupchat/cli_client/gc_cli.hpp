#pragma once

#include "cmd_data.hpp"

#include <flat_map>
#include "gc_cli_config.hpp"
#include "cli_window.hpp"
#include "cli_groupchat.hpp"

#include <securepath/console/context.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/event_system/event_loop.hpp>

#include <chrono>
#include <memory>

namespace securepath::groupchat {

class gc_cli : public console::context, public event_system::event_handler {
public:
	gc_cli(gc_cli_config);
	~gc_cli();

	void run();

	bool handle_input(console::input in);
private:
	void add_command(std::wstring const& cmd, std::size_t, cmd_func f);
	void init_commands();
	void handle_event(std::unique_ptr<event_base>) override;
	void handle_command(std::wstring input);
	void execute_command(std::wstring cmd, std::vector<std::wstring_view> const& args);

	void create_account(std::vector<std::wstring_view> const& args);
	void connect(std::vector<std::wstring_view> const& args);
	void disconnect(std::vector<std::wstring_view> const& args);
	void add_contact(std::vector<std::wstring_view> const& args);
	void show_contacts(std::vector<std::wstring_view> const& args);
	void show_requests(std::vector<std::wstring_view> const& args);

	void create_chat(std::vector<std::wstring_view> const& args);
	void show_chats(std::vector<std::wstring_view> const& args);
	void manage_chat(std::vector<std::wstring_view> const& args);
	void manage_window(std::vector<std::wstring_view> const& args);
	void send_message(std::string_view message);
	/// the chat of the current window, its window number in ch
	channel& current_chat(int& ch);
	void share_file(std::vector<std::wstring_view> const& args);
	void show_files(std::vector<std::wstring_view> const& args);
	void get_file(std::vector<std::wstring_view> const& args);
	void unfetch_file(std::vector<std::wstring_view> const& args);

	void add_member(std::vector<std::wstring_view> const& args);
	void invite(std::vector<std::wstring_view> const& args);
	void join_chat(std::vector<std::wstring_view> const& args);
	void my_info(std::vector<std::wstring_view> const& args);
	void help(std::vector<std::wstring_view> const& args);

	static std::vector<sync_replica> parse_fallbacks(std::vector<std::string> const&);
	static gc_servers account_servers(gc_cli_config const&);
private:
	gc_cli_config const config_;
	std::unique_ptr<cli_window> win_;
	std::unique_ptr<cli_groupchat> gc_;
	std::flat_map<std::wstring, cmd_data> cmds_;
};

}