#include "gc_cli.hpp"
#include <spsync/util/print.hpp>

#include <spsync/client/protocol/contact.hpp>

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
, config_(config)
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
		if(!config.fallbacks.empty()) {
			gc_->set_fallback_servers(parse_fallbacks(config.fallbacks));
		}
		for(auto const& r : gc_->fallback_servers()) {
			win_->add_info(0, to_wstring(print("replica of the home server: %", format_replica(r))));
		}
		gc_->connect();
	}
}

std::vector<sync_replica> gc_cli::parse_fallbacks(std::vector<std::string> const& texts) {
	std::vector<sync_replica> ret;
	for(auto const& t : texts) {
		ret.push_back(parse_sync_replica(t));
	}
	return ret;
}

gc_servers gc_cli::account_servers(gc_cli_config const& config) {
	auto servers = default_servers();
	if(!config.server.empty()) {
		servers.host = config.server;
	}
	if(config.keyport) {
		servers.key_server_port = static_cast<std::uint16_t>(config.keyport);
	}
	if(config.syncport) {
		servers.sync_server_port = static_cast<std::uint16_t>(config.syncport);
	}
	if(config.packetport) {
		servers.packet_server_port = static_cast<std::uint16_t>(config.packetport);
	}
	servers.fallbacks = parse_fallbacks(config.fallbacks);
	return servers;
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

	add_command(L"create-chat", 1, [this](auto v){ create_chat(v); });
	add_command(L"invite", 1, [this](auto v){ invite(v); });
	add_command(L"chats", 0, [this](auto v){ show_chats(v); });
	add_command(L"join", 1, [this](auto v){ join_chat(v); });

	add_command(L"chat", 1, [this](auto v){ manage_chat(v); });
	add_command(L"window", 1, [this](auto v){ manage_window(v); });

	add_command(L"account", 0, [this](auto v){ my_info(v); });
}

void gc_cli::create_account(std::vector<std::wstring_view> const& args) {
	auto acc = gc_->account_info();
	if(acc) {
		LOG_WARN("account already exists");
		throw make_error(errc::constraint_violation, "account already exists");
	} else {
		gc_->create_account(account_servers(config_), to_string(args[0]));
		win_->add_info(0, L"account created successfully");
	}
}

void gc_cli::connect(std::vector<std::wstring_view> const& args) {
	auto info = gc_->account_info();
	if(info) {
		gc_->connect();
	} else {
		win_->add_info(0, L"no account");
	}
}

void gc_cli::disconnect(std::vector<std::wstring_view> const& args) {
	auto info = gc_->account_info();
	if(info) {
		gc_->disconnect();
	} else {
		win_->add_info(0, L"no account");
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
		// contacts are looked up at the key server of our own account
		user receiver{key_id, gc_->account_info()->me.key_server()};
		gc_->request_handler().add_contact(receiver, name, message);
		win_->add_info(0, L"added contact '" + to_wstring(name) + L"'");
	}
}

void gc_cli::show_contacts(std::vector<std::wstring_view> const& args) {
	if(gc_->account_info()) {
		win_->add_info(0, L"contacts:");
		auto contacts = gc_->contacts().enumerate();
		for(auto& v : contacts) {
			std::string key_id = v->id().public_key_id().in_hex();
			std::string name = v->name();
			win_->add_message(0, to_wstring(print("  name='%' key_id='%'", name, key_id)));
		}
	} else {
		win_->add_info(0, L"no account");
	}
}

void gc_cli::show_requests(std::vector<std::wstring_view> const& args) {
	win_->add_info(0, L"Requests:");
	auto list = gc_->requests().enumerate();
	for(auto&& v : list) {
		if(v.tag == sync::client::contact_tag) {
			auto data = serialisation::asn_der_deserialise<sync::client::protocol::contact_data>(v.data);
			win_->add_info(0, print("  % type=Contacting, sender=% (%)", v.id, data.name, v.sender.id().public_key_id().in_hex()));
		} else if(v.tag == sync::client::invite_tag) {
			auto data = serialisation::asn_der_deserialise<sync::client::protocol::invitation_data>(v.data);
			win_->add_info(0, print("  % type=Chat invitation, sender=% (%)", v.id, data.name, v.sender.id().public_key_id().in_hex()));
		}
	}
}

// the creation needs the live connection (the request is sent right away): connect and
// create once connected
void gc_cli::create_chat(std::vector<std::wstring_view> const& args) {
	std::string name{to_string(args.front())};
	auto conn = gc_->load();
	conn->connect();
	gc_->run_when_connected(conn->id(), [this, conn, name] {
		try {
			auto cid = conn->create_chat(name, sync::users{}).id();
			int ch = gc_->add_channel(cid, name);
			win_->change_channel(name, ch);
			win_->add_info(ch, print("created chat '%' with id=%", name, to_hex(cid)));
		} catch(std::exception const& ex) {
			win_->add_info(0, to_wstring(print("creating chat '%' failed: %", name, ex.what())));
		}
		redraw();
	});
}

void gc_cli::show_chats(std::vector<std::wstring_view> const& args) {
	win_->add_info(0, L"Chats:");
	for(auto const& c : gc_->connections()) {
		for(auto const& c_id : c->channel_ids()) {
			channel& ch = c->get(c_id);
			win_->add_info(0, print("  % (%)", ch.name(), to_hex(ch.id())));
		}
	}
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

// invite a user (public key id in hex, looked up at our key server) to the chat of the
// current window; the invitation travels through the packet server
void gc_cli::invite(std::vector<std::wstring_view> const& args) {
	int ch = win_->current_channel();
	auto cid = ch ? gc_->map_to_cid(ch) : std::optional<chat_id>{};
	if(!cid) {
		throw make_error(errc::invalid_state, "select a chat window first");
	}
	crypto::public_key_id key_id{to_string(args[0])};
	auto message = args.size() > 1 ? to_string(args[1]) : "";
	gc_->send_chat_invitation(user{key_id, gc_->account_info()->me.key_server()}, message, *cid);
	win_->add_info(ch, print("invited % to the chat", key_id.in_hex()));
}

void gc_cli::join_chat(std::vector<std::wstring_view> const& args) {
	auto rid = std::stoll(to_string(args[0]));
	auto info = gc_->join_chat(rid);
	// join_chat loads the chat connection without connecting it (doc/todos.txt); the
	// channel synchronises once the connection is up
	auto hp = gc_->channel_ids().find_server(info.cid);
	if(hp) {
		gc_->load(*hp)->connect();
	}
	int ch = gc_->add_channel(info.cid, info.name);
	win_->change_channel(info.name, ch);
}

void gc_cli::manage_chat(std::vector<std::wstring_view> const& args) {
	if(args.front() == L"open") {
		if(args.size() < 2) {
			throw make_error(errc::invalid_argument, "missing argument for /chat open");
		}
		auto cid = from_hex(to_string(args[1]));
		auto hp = gc_->channel_ids().find_server(cid);
		if(!hp) {
			LOG_TRACE("no chat with id {}", to_hex(cid));
			throw make_error(errc::no_such_data, "could not find chat");
		}
		auto conn = gc_->load(*hp);
		conn->connect();
		auto& channel = conn->get(cid);
		int ch = gc_->add_channel(cid, channel.name());
		win_->change_channel(channel.name(), ch);
	}
}

void gc_cli::manage_window(std::vector<std::wstring_view> const& args) {
	if(args.front() == L"close") {
		int ch = win_->current_channel();
		if(ch) {
			gc_->remove_channel(ch);
			win_->change_channel("", 0);
		}
	} else {
		int ch = 0;
		try {
			ch = std::stoi(to_string(args[0]));
		} catch(std::exception const&) {
			throw make_error(errc::invalid_argument, "invalid /window command");
		}
		auto cid = gc_->map_to_cid(ch);
		win_->change_channel(cid ? to_hex(*cid) : std::string{}, ch);
	}
}

void gc_cli::send_message(std::string_view message) {
	int ch = win_->current_channel();
	if(ch) {
		auto cid = gc_->map_to_cid(ch);
		if(cid) {
			auto hp = gc_->channel_ids().find_server(*cid);
			if(!hp) {
				LOG_TRACE("no chat with id {}", to_hex(*cid));
				throw make_error(errc::no_such_data, "could not find chat");
			}
			auto conn = gc_->load(*hp);
			auto& channel = conn->get(*cid);
			channel.send_message(message);
			win_->add_message(ch, std::format("--> {}", message));
		}
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
				send_message(to_string(input));
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
