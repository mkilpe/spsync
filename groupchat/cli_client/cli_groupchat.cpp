#include "cli_groupchat.hpp"

#include <groupchat/core/events.hpp>
#include <spsync/client/events.hpp>

#include <securepath/util/string_util.hpp>
#include <securepath/util/print_util.hpp>

namespace securepath::groupchat {

cli_groupchat::cli_groupchat(event_system::event_loop& loop, cli_window& win, gc_cli_config config)
: event_handler(loop)
, groupchat(*this, groupchat_config{.path=config.path})
, win_(win)
, config_(config)
{
}

cli_groupchat::~cli_groupchat() {
	stop_handler();
}

void cli_groupchat::on_connect() {
	win_.add_info(0, L"connected to server");
}

void cli_groupchat::on_disconnect(error err) {
	auto s = print("disconnected from server (error=%)", err);
	win_.add_info(0, to_wstring(s));
}

void cli_groupchat::on_init(server_chat_id id, error err) {
	std::string msg;
	if(err) {
		msg = print("failed to create chat (id=%, error=%)", to_hex(id.cid), err);
	} else {
		msg = print("created chat with id %", to_hex(id.cid));
	}
	win_.add_info(0, to_wstring(msg));
}

void cli_groupchat::on_change_user(server_chat_id id, sync::users change, error err) {
	std::string msg;
	if(err) {
		msg = print("failed to change user (id=%, error=%)", to_hex(id.cid), err);
	} else {
		msg = print("changed users for chat with id %", to_hex(id.cid));
	}
	win_.add_info(0, to_wstring(msg));
}

void cli_groupchat::on_join(server_chat_id id, sync::users change, error) {
	auto s = print("joined '%'", to_hex(id.cid));
	win_.add_message(0, to_wstring(s));
}

void cli_groupchat::on_message(server_chat_id, msg_data md, msg_change change) {
	//auto s = print("%> %", m.sender_nick, m.data);
	//win_.add_message(0, to_wstring(s));
}

void cli_groupchat::on_contacting(sync::client::request const& req
		, std::string const& name
		, std::string const& message)
{
	auto s = print("[rid=%] received contacting from '%' (%)", req.id, name, req.sender.id().public_key_id().in_hex());
	win_.add_message(0, to_wstring(s));
}

void cli_groupchat::handle_event(std::unique_ptr<event_system::event_base> ev) {
	dispatch( *ev
			, event_dest<sync::client::events::on_connect>(&cli_groupchat::on_connect)
			, event_dest<sync::client::events::on_disconnect>(&cli_groupchat::on_disconnect)
			, event_dest<sync::client::events::on_contacting>(&cli_groupchat::on_contacting)
			, event_dest<events::on_init>(&cli_groupchat::on_init)
			, event_dest<events::on_change_user>(&cli_groupchat::on_change_user)
			, event_dest<events::on_join>(&cli_groupchat::on_join)
			, event_dest<events::on_message>(&cli_groupchat::on_message) );
}

}