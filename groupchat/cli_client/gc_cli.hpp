#pragma once

#include <securepath/console/text_window.hpp>

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
	void handle_event(std::unique_ptr<event_base>) override;
	void handle_command(std::wstring input);
	void execute_command(std::wstring_view cmd, std::vector<std::wstring_view> const& args);
private:
	std::shared_ptr<console::text_window> text_area_;
};

}