#pragma once

#include "cli_window.hpp"
#include "gc.hpp"

#include <securepath/console/context.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/event_system/event_loop.hpp>

namespace securepath::groupchat {

struct gc_cli_config {

};

class gc_cli : public console::context, public event_system::event_handler {
public:
	gc_cli(gc_cli_config);

	void run();

	bool handle_input(console::input in);
private:
	void init_commands();
	void handle_event(std::unique_ptr<event_base>) override;
	void handle_command(std::wstring input);
	void execute_command(std::wstring cmd, std::vector<std::wstring_view> const& args);

	void connect(std::vector<std::wstring_view> const& args);
	void create_chat(std::vector<std::wstring_view> const& args);
	void add_user(std::vector<std::wstring_view> const& args);
	void add_member(std::vector<std::wstring_view> const& args);
	void join(std::vector<std::wstring_view> const& args);
	void my_info(std::vector<std::wstring_view> const& args);
private:
	std::unique_ptr<cli_window> win_;
	std::unique_ptr<gc> gc_;
	std::map<std::wstring, std::function<void (std::vector<std::wstring_view> const&)>> cmds_;
	std::shared_ptr<chat_connection> chat_conn_;
	chat_id cid_;
};

}