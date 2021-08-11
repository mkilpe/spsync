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

	init_commands();
	// modes need to be set before constructing the windows
	win_ = std::make_unique<cli_window>(*this);
	gc_  = std::make_unique<gc>(static_cast<event_system::event_loop&>(*this), *win_);

	auto size = screen_size();
	auto in = std::make_shared<input>(*this, console::point{0, size.y-1}, size.x);

	add_widget(in);
	set_focus(in);
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

void gc_cli::init_commands() {
	cmds_[L"exit"] = [this](auto){ quit(); };
	cmds_[L"connect"] = [this](auto v){ connect(v); };
	cmds_[L"disconnect"] = [this](auto){ gc_->disconnect(1); };
	cmds_[L"create-chat"] = [this](auto v){ create_chat(v); };
}

void gc_cli::connect(std::vector<std::wstring_view> const& args) {
	std::uint16_t const default_storage_server_port{18200};

	if(!args.empty()) {
		std::wstring host{args.front()};
		win_->add_info(0, L"connecting to " + host + L"...");
		gc_->connect(to_string(host), default_storage_server_port);
	} else {
		win_->add_info(0, L"missing argument(s) for /connect");
	}
}

void gc_cli::create_chat(std::vector<std::wstring_view> const& args) {
	if(!args.empty()) {
		std::wstring name{args.front()};
		cid_ = gc_->create_chat(1, name);
		win_->add_info(0, L"creating chat '" + name + L"' with id=" + to_wstring(to_hex(cid_)));
	} else {
		win_->add_info(0, L"missing argument(s) for /create-chat");
	}
}

void gc_cli::execute_command(std::wstring cmd, std::vector<std::wstring_view> const& args) {
	auto it = cmds_.find(cmd);
	if(it != cmds_.end()) {
		it->second(args);
	} else {
		win_->add_info(0, L"invalid command");
	}
}

void gc_cli::handle_command(std::wstring input) {
	if(!input.empty()) {
		if(input[0] == L'/') {
			std::wstring cmd = input.substr(1);
			auto res = tokenise_view(cmd);
			if(!res.empty()) {
				execute_command(std::wstring{res[0]}, {res.begin()+1, res.end()});
			}
		} else {
			gc_->send_message(1, cid_, to_string(input));
			win_->add_message(0, std::move(input));
		}
		redraw();
	}
}

void gc_cli::handle_event(std::unique_ptr<event_base> ev) {
	dispatch(*ev
			, event_dest<console::events::input>(&gc_cli::handle_command));
}

}
