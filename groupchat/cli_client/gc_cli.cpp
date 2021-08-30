#include "gc_cli.hpp"

#include <securepath/console/input_line.hpp>
#include <securepath/console/text_window.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/string_util.hpp>
#include <securepath/util/print_util.hpp>

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

	std::uint16_t const default_storage_server_port{18200};
	chat_conn_ = gc_->load("127.0.0.1", default_storage_server_port);
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
	cmds_[L"disconnect"] = [this](auto){ chat_conn_->disconnect(); };
	cmds_[L"create-chat"] = [this](auto v){ create_chat(v); };
	cmds_[L"add-user"] = [this](auto v){ add_user(v); };
	cmds_[L"add-member"] = [this](auto v){ add_member(v); };
	cmds_[L"join"] = [this](auto v){ join(v); };
	cmds_[L"my-info"] = [this](auto v){ my_info(v); };
}

void gc_cli::connect(std::vector<std::wstring_view> const& args) {
	host_port hp = chat_conn_->end_point();
	win_->add_info(0, to_wstring(print("connecting to %:%...", hp.host, hp.port)));
	chat_conn_->connect();
}

void gc_cli::create_chat(std::vector<std::wstring_view> const& args) {
	if(!args.empty()) {
		std::wstring name{args.front()};
		cid_ = chat_conn_->create_chat(to_string(name));
		win_->add_info(0, L"creating chat '" + name + L"' with id=" + to_wstring(to_hex(cid_)));
	} else {
		win_->add_info(0, L"missing argument(s) for /create-chat");
	}
}

void gc_cli::add_user(std::vector<std::wstring_view> const& args) {

}

// add member to chat
void gc_cli::add_member(std::vector<std::wstring_view> const& args) {
	if(args.size() == 2) {
		auto& context = gc_->context();
		auto key = context.private_data().my_private_key();
		assert(key);

		using namespace sync::util;

		sync::users users;
		users.add(user_access{user_id{key->id()}, access_type::all_access});

		crypto::public_key_id key_id{from_hex(to_string(args[1]))};
		users.add(user_access{user_id{key_id}, access_type::all_access});

		chat_conn_->change_user(from_hex(to_string(args[0])), users);
	} else {
		win_->add_info(0, L"missing argument(s) for /add-member");
	}
}

void gc_cli::join(std::vector<std::wstring_view> const& args) {
	if(args.size() == 1) {
		cid_ = from_hex(to_string(args[0]));
		chat_conn_->join(cid_);
	} else {
		win_->add_info(0, L"missing argument(s) for /join");
	}
}

void gc_cli::my_info(std::vector<std::wstring_view> const& args) {
	auto& context = gc_->context();
	auto key = context.private_data().my_private_key();
	if(key) {
		auto s = print("my key is '%'", key->id());
		win_->add_info(0, to_wstring(s));
	} else {
		win_->add_info(0, L"no key set yet");
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
			chat_conn_->send_message(cid_, to_string(input));
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
