#include "gc_cli.hpp"

#include <securepath/console/input_line.hpp>
#include <securepath/console/text_window.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/string_util.hpp>
#include <securepath/util/print_util.hpp>
#include <securepath/common/version_number.hpp>

namespace securepath::groupchat {

version_number const gc_cli_version{0,0,1,"alpha"};

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

gc_cli::gc_cli(gc_cli_config config)
: event_handler(static_cast<event_system::event_loop&>(*this))
{
	set_mode(console::mode::nodelay | console::mode::cbreak | console::mode::noecho | console::mode::colours);

	init_commands();
	// modes need to be set before constructing the windows
	win_ = std::make_unique<cli_window>(*this);
	gc_  = std::make_unique<cli_groupchat>(static_cast<event_system::event_loop&>(*this), *win_, config);

	// add info channel, index 0
	win_->add_channel(L"Info");

	auto size = screen_size();
	auto in = std::make_shared<input>(*this, console::point{0, size.y-1}, size.x);

	add_widget(in);
	set_focus(in);

	win_->add_info(0, to_wstring(print("Welcome to gc_cli [version %]", gc_cli_version)));

	if(gc_->account_info()) {
		gc_->connect();
	}
}

gc_cli::~gc_cli() {
	stop_handler();
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

void gc_cli::add_command(std::wstring const& cmd, std::size_t req, cmd_func f) {
	cmds_.emplace(cmd, cmd_data(cmd, std::move(f), req));
}

void gc_cli::init_commands() {
	add_command(L"help", 0, [this](auto v){ help(v); });
	add_command(L"exit", 0, [this](auto){ quit(); });
	add_command(L"connect", 0, [this](auto v){ connect(v); });
	add_command(L"create-account", 1, [this](auto v){ create_account(v); });
	add_command(L"disconnect", 0, [this](auto v){ disconnect(v); });
	add_command(L"add-contact", 2, [this](auto v){ add_contact(v); });
	add_command(L"contacts", 0, [this](auto v){ show_contacts(v); });
	add_command(L"requests", 0, [this](auto v){ show_requests(v); });

	//add_command(L"create-chat", [this](auto v){ create_chat(v); });
	//add_command(L"add-member", [this](auto v){ add_member(v); });
	//add_command(L"join", [this](auto v){ join(v); });
	add_command(L"account", 0, [this](auto v){ my_info(v); });
}

void gc_cli::create_account(std::vector<std::wstring_view> const& args) {
	auto acc = gc_->account_info();
	if(acc) {
		LOG_WARN("account already exists");
		throw make_error(errc::constraint_violation, "account already exists");
	} else {
		gc_->create_account(default_servers(), to_string(args[0]));
		win_->add_info(0, L"account created successfully");
	}
}

void gc_cli::connect(std::vector<std::wstring_view> const& args) {
	gc_->connect();
}

void gc_cli::disconnect(std::vector<std::wstring_view> const& args) {
	gc_->disconnect();
}

void gc_cli::create_chat(std::vector<std::wstring_view> const& args) {
	if(!args.empty()) {
		std::wstring name{args.front()};
		//win_->add_info(0, L"creating chat '" + name + L"' with id=" + to_wstring(to_hex(cid_)));
	} else {
		win_->add_info(0, L"missing argument(s) for /create-chat");
	}
}

void gc_cli::add_contact(std::vector<std::wstring_view> const& args) {
		auto name = to_string(args[0]);
		auto key_id_string = to_string(args[1]);
		auto message = args.size() > 2 ? to_string(args[2]) : "";

		crypto::public_key_id key_id{key_id_string};
		auto contact = gc_->contacts().find(key_id);

		if(contact && contact->state() == sync::client::contact_state::complete) {
			win_->add_info(0, L"contact already exists");
		} else {
			user receiver{key_id, default_servers().key_server()};
			gc_->request_handler().add_contact(receiver, name, message);
			win_->add_info(0, L"added contact '" + to_wstring(name) + L"'");
		}
}

void gc_cli::show_contacts(std::vector<std::wstring_view> const& args) {
	win_->add_info(0, L"contacts:");
	auto contacts = gc_->contacts().enumerate();
	for(auto& v : contacts) {
		std::string key_id = v->id().public_key_id().in_hex();
		std::string name = v->name();
		win_->add_message(0, to_wstring(print("  name='%' key_id='%'", name, key_id)));
	}
}

void gc_cli::show_requests(std::vector<std::wstring_view> const& args) {

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

		//chat_conn_->change_user(from_hex(to_string(args[0])), users);
	} else {
		win_->add_info(0, L"missing argument(s) for /add-member");
	}
}

void gc_cli::join(std::vector<std::wstring_view> const& args) {
	if(args.size() == 1) {
		//cid_ = from_hex(to_string(args[0]));
		//chat_conn_->join(cid_);
	} else {
		win_->add_info(0, L"missing argument(s) for /join");
	}
}

void gc_cli::my_info(std::vector<std::wstring_view> const& args) {
	auto info = gc_->account_info();
	if(info) {
		if(args.size() == 1 && args[0] == L"qr-code") {
			//todo
		} else {
			win_->add_info(0, to_wstring(print("name='%' key_id='%'", info->name, info->me.id().public_key_id().in_hex())));
		}
	} else {
		win_->add_info(0, L"no account");
	}
}

void gc_cli::help(std::vector<std::wstring_view> const& args) {
	win_->add_info(0, L"Commands:");
	for(auto c : cmds_) {
		win_->add_info(0, L"  " + c.first);
	}
}

void gc_cli::execute_command(std::wstring cmd, std::vector<std::wstring_view> const& args) {
	auto it = cmds_.find(cmd);
	if(it != cmds_.end()) {
		it->second.call(args);
	} else {
		win_->add_info(0, L"invalid command");
	}
}

void gc_cli::handle_command(std::wstring input) {
	if(!input.empty()) {
		try {
			if(input[0] == L'/') {
				std::wstring cmd = input.substr(1);
				auto res = tokenise_view(cmd);
				if(!res.empty()) {
					execute_command(std::wstring{res[0]}, {res.begin()+1, res.end()});
				}
			} else {
				//chat_conn_->get(cid_).send_message(to_string(input));
				win_->add_message(0, std::move(input));
			}
		} catch(error const& err) {
			win_->add_info(0, to_wstring(err.message()));
		} catch(std::exception const& ex) {
			win_->add_info(0, L"exception: " + to_wstring(ex.what()));
		}
		redraw();
	}
}

void gc_cli::handle_event(std::unique_ptr<event_base> ev) {
	dispatch(*ev
			, event_dest<console::events::input>(&gc_cli::handle_command));
}

}
