#include "channel.hpp"
#include "groupchat.hpp"
#include "events.hpp"

#include <spsync/core/records/util.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <spsync/client/record_util.hpp>

#include <securepath/util/conversions.hpp>
#include <securepath/util/string_util.hpp>

namespace securepath::groupchat {

std::string const gc_name_tag = "gc.chat.name";

channel::channel(server_id sid, event_system::event_handler& callback, network::context& context, chat_id const& cid)
: client_sync(callback.event_loop(), database::sqlite::create_sqlite_connection(to_hex(cid) + ".db"))
, callback_(callback)
, context_(context)
, sid_(sid)
, chat_id_(cid)
{
}

channel::~channel() {
	stop_handler();
}

void channel::set_name(std::string name) {
	insert(gc_name_tag, name);
}

void channel::on_data_change(sync::record_handle rec, std::deque<sync::single_data_change> changes) {
	LOG_TRACE("on_object_data_changed");
	//t: handle nick etc
	for(auto const& c : changes) {
		auto opt = c.header.metadata().find<message_data>(groupchat_message_id);
		if(opt) {
			message m{opt->message, "test", opt->sender_time, rec->block_id().sequence};
			callback_.emit<events::on_message>(sid_, chat_id_, m);
		} else {
			LOG_WARN("invalid record, no groupchat message found");
		}
	}
}

void channel::on_user_change(sync::record_handle, sync::user_change usc) {
	callback_.emit<events::on_change_user>(sid_, chat_id_, usc.members, error{});
}

void channel::create_initial_record() {
	auto own_key = context_.private_data().my_private_key();
	assert(own_key);
	sync::metadata header;
	header.insert(groupchat_name_id, find<std::string>(gc_name_tag).value_or(to_hex(chat_id_)));
	sync::users initial;
	initial.add(sync::util::user_access{own_key->id(), sync::util::access_type::user_management_access});
	send_user_change(std::move(initial), std::move(header));
}

message_id channel::send_message(std::string const& msg) {
	message_data chat_msg{msg, clock_type::now()};
	sync::metadata header;
	header.insert(groupchat_message_id, chat_msg);
	auto msg_id = sync::util::create_object_id();
	send_data_change(msg_id, std::move(header));
	return msg_id;
}

chat_id channel::id() const {
	return chat_id_;
}

}