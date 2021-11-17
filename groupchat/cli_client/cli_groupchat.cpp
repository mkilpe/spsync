#include "cli_groupchat.hpp"

#include <groupchat/core/events.hpp>

#include <securepath/util/string_util.hpp>
#include <securepath/util/print_util.hpp>

namespace securepath::groupchat {

cli_groupchat::cli_groupchat(event_system::event_loop& loop, cli_window& win)
: event_handler(loop)
, groupchat(*this, groupchat_config{})
, win_(win)
{
}

cli_groupchat::~cli_groupchat() {
	stop_handler();
}

void cli_groupchat::on_connect(server_id sid) {
	win_.add_info(0, L"connected to server");
}

void cli_groupchat::on_disconnect(server_id sid, error err) {
	auto s = print("disconnected from server (error=%)", err);
	win_.add_info(0, to_wstring(s));
}

void cli_groupchat::on_create(server_id sid, chat_id cid, error err) {
	std::string msg;
	if(err) {
		msg = print("failed to create chat (id=%, error=%)", to_hex(cid), err);
	} else {
		msg = print("created chat with id %", to_hex(cid));
	}
	win_.add_info(0, to_wstring(msg));
}

void cli_groupchat::on_change_user(server_id sid, chat_id cid, sync::users change, error err) {
	std::string msg;
	if(err) {
		msg = print("failed to change user (id=%, error=%)", to_hex(cid), err);
	} else {
		msg = print("changed users for chat with id %", to_hex(cid));
	}
	win_.add_info(0, to_wstring(msg));
}

void cli_groupchat::on_join(server_id sid, chat_id cid, error) {
	auto s = print("joined '%'", to_hex(cid));
	win_.add_message(0, to_wstring(s));
}

void cli_groupchat::on_message(server_id, chat_id, msg_data md, msg_change change) {
	//auto s = print("%> %", m.sender_nick, m.data);
	//win_.add_message(0, to_wstring(s));
}

void cli_groupchat::handle_event(std::unique_ptr<event_system::event_base> ev) {
	dispatch( *ev
			, event_dest<events::on_connect>(&cli_groupchat::on_connect)
			, event_dest<events::on_disconnect>(&cli_groupchat::on_disconnect)
			, event_dest<events::on_init>(&cli_groupchat::on_create)
			, event_dest<events::on_change_user>(&cli_groupchat::on_change_user)
			, event_dest<events::on_join>(&cli_groupchat::on_join)
			, event_dest<events::on_message>(&cli_groupchat::on_message) );
}

}