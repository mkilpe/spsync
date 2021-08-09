#include "gc.hpp"

namespace securepath::groupchat {

gc::gc(event_system::event_loop& loop, cli_window& win)
: groupchat(groupchat_config{}, loop)
, win_(win)
{
}

void gc::on_connect(server_id sid) {

}

void gc::on_disconnect(server_id sid, error err) {

}

void gc::on_create(server_id sid, chat_id cid, error err) {

}

void gc::on_change_user(server_id sid, chat_id cid, sync::users change, error err) {

}

void gc::on_join(server_id sid, chat_id cid) {

}

void gc::on_message(server_id, chat_id, message) {

}

}