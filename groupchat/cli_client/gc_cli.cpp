#include "gc_cli.hpp"

#include <securepath/console/input_line.hpp>
#include <securepath/console/text_window.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/string_util.hpp>

namespace securepath::groupchat {

struct input : console::input_line {
public:
	input(gc_cli& parent, console::point pos, std::size_t size)
	: input_line(parent, pos, size)
	, parent(parent)
	{}

	void key_event(console::input in) {
		if(!parent.handle_input(in)) {
			input_line::key_event(in);
		}
	}

public:
	gc_cli& parent;
};

gc_cli::gc_cli(gc_cli_config)
: event_handler(static_cast<event_system::event_loop&>(*this))
{
	set_mode(console::mode::nodelay | console::mode::cbreak | console::mode::noecho | console::mode::colours);

	auto size = screen_size();
	auto in = std::make_shared<input>(*this, console::point{0, size.y-1}, size.x);
	text_area_ = std::make_shared<console::text_window>(console::rect{console::point{0,0}, {size.x, size.y-1}});

	add_widget(text_area_);
	add_widget(in);
	set_focus(in);

	text_area_->add_line(L"Welcome to group chat");
}

void gc_cli::run() {
	thread_entry();
}

bool gc_cli::handle_input(console::input in) {
	bool ret = false;
	if(in.key == console::input_key::esc) {
		quit();
		ret = true;
	}
	return ret;
}

void gc_cli::execute_command(std::wstring_view cmd, std::vector<std::wstring_view> const& args) {

	if(cmd == L"exit") {
		quit();
	}
}

void gc_cli::handle_command(std::wstring input) {
	if(!input.empty()) {
		if(input[0] == L'/') {
			std::wstring cmd = input.substr(1);
			auto res = tokenise_view(cmd);
			if(!res.empty()) {
				execute_command(res[0], {res.begin()+1, res.end()});
			}
		} else {
			text_area_->add_line(std::move(input));
		}
		redraw();
	}
}

void gc_cli::handle_event(std::unique_ptr<event_base> ev) {
	dispatch(*ev
			, event_dest<console::events::input>(&gc_cli::handle_command));
}

}
