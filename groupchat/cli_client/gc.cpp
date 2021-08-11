#include "gc.hpp"

#include <securepath/util/string_util.hpp>
#include <securepath/util/print_util.hpp>

namespace securepath::groupchat {

gc::gc(event_system::event_loop& loop, cli_window& win)
: groupchat(groupchat_config{}, loop)
, win_(win)
{
}

void gc::on_connect(server_id sid) {
	win_.add_info(0, L"connected to server");
}

void gc::on_disconnect(server_id sid, error err) {
	auto s = print("disconnected from server (error=%)", err);
	win_.add_info(0, to_wstring(s));
}

void gc::on_create(server_id sid, chat_id cid, error err) {
	std::string msg;
	if(err) {
		msg = print("failed to create chat (id=%, error=%)", to_hex(cid), err);
	} else {
		msg = print("created chat with id %", to_hex(cid));
	}
	win_.add_info(0, to_wstring(msg));
}

void gc::on_change_user(server_id sid, chat_id cid, sync::users change, error err) {
	std::string msg;
	if(err) {
		msg = print("failed to change user (id=%, error=%)", to_hex(cid), err);
	} else {
		msg = print("changed users for chat with id %", to_hex(cid));
	}
	win_.add_info(0, to_wstring(msg));
}

void gc::on_join(server_id sid, chat_id cid) {

}

void gc::on_message(server_id, chat_id, message m) {
	auto s = print("%> %", m.sender_nick, m.data);
	win_.add_message(0, to_wstring(s));
}

}