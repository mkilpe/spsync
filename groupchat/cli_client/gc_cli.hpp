#pragma once

#include "cmd_data.hpp"
#include "gc_cli_config.hpp"
#include "cli_window.hpp"
#include "cli_groupchat.hpp"

#include <securepath/console/context.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/event_system/event_loop.hpp>

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

	void add_member(std::vector<std::wstring_view> const& args);
	void join(std::vector<std::wstring_view> const& args);
	void my_info(std::vector<std::wstring_view> const& args);
	void help(std::vector<std::wstring_view> const& args);
private:
	std::unique_ptr<cli_window> win_;
	std::unique_ptr<cli_groupchat> gc_;
	std::map<std::wstring, cmd_data> cmds_;
};

}