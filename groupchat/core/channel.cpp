#include "channel.hpp"
#include "groupchat.hpp"
#include "events.hpp"

#include <spsync/core/records/util.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <spsync/client/record_util.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/conversions.hpp>
#include <securepath/util/string_util.hpp>

namespace securepath::groupchat {

std::string const gc_name_tag = "gc.chat.name";

static database::connection_ptr open_db(chat_conn_context& context, chat_id const& cid) {
	std::string path = context.path.empty() ? "" : context.path + "/";
	return database::sqlite::create_sqlite_connection(path + to_hex(cid) + ".db");
}

channel::channel(chat_conn_context& context, chat_id const& cid)
: channel(context, cid, open_db(context, cid))
{
}

channel::channel(chat_conn_context& context, chat_id const& cid, database::connection_ptr db)
: client_sync(
	context.context,
	context.callback.event_loop(),
	db,
	sync::sync_engine_config{.auth_mode=sync::auth_mode::sign_records, .log_id=to_hex(cid)})
, ccontext_(context)
, chat_id_(cid)
, messages_(db)
, db_(db)
, my_key_id_(my_private_key(context.context.private_data()).id())
{
	// make sure we are in sync with record storage and messages storage in case the application
	// was interrupted in between updating the messages storage
	sync_message_storage(messages_, crypto_context().records(), crypto_context().enc_keys());
}

channel::~channel() {
	stop_handler();
}

std::string channel::name() const {
	return find<std::string>(gc_name_tag).value_or(to_hex(chat_id_));
}

void channel::set_data(std::string name, users members) {
	insert(gc_name_tag, name);

	std::unique_lock l{mutex_};
	initial_members_ = members;
}

void channel::on_data_change(sync::record_handle rec, std::deque<sync::single_data_change> changes) {
	LOG_TRACE("on_object_data_changed [count=%]", changes.size());

	std::unique_lock l{mutex_};
	database::transaction t{*db_};

	for(auto const& c : changes) {
		// check the previous oid for data record to ensure compatibility in the later versions when we do use it
		if(c.data.previous_oid_record_tag.empty()) {
			auto opt = c.header.metadata().find<message_data>(groupchat_message_id);
			if(opt) {
				// insert to message storage
				msg_data data{*opt, c.signer.value_or(crypto::public_key_id{}), c.internal_id, c.seq};
				auto change = messages_.insert(c.data.id, data, msg_state::in_sync);
				// notify higher level
				ccontext_.callback.emit<events::on_message>(ccontext_.sid, chat_id_, data, change);
			} else {
				LOG_WARN("invalid record, no groupchat message found");
			}
		} else {
			LOG_WARN("data record with parent? (using old version of client?)");
		}
	}
}

void channel::on_user_change(sync::record_handle rec, sync::user_change usc) {
	if(rec->block_id().sequence == sync::sequence_number{1}) {
		if(usc.signer) {
			// check if we created the chat or not
			auto my_key = my_private_key(ccontext_.context.private_data());
			if(usc.signer != my_key.id()) {
				ccontext_.callback.emit<events::on_join>(ccontext_.sid, chat_id_, error{});
			}
		}
	}
	ccontext_.callback.emit<events::on_change_user>(ccontext_.sid, chat_id_, usc.members, error{});
}

void channel::create_initial_record() {
	auto own_key = ccontext_.context.private_data().my_private_key();
	assert(own_key);
	sync::metadata header;
	header.insert(groupchat_name_id, find<std::string>(gc_name_tag).value_or(to_hex(chat_id_)));

	std::unique_lock l{mutex_};
	sync::users initial = initial_members_;
	// always add ourself
	initial.add(sync::util::user_access{own_key->id(), sync::util::access_type::user_management_access});
	send_user_change(std::move(initial), std::move(header));
}

message channel::send_message(std::string const& msg) {
	message_data chat_msg{msg, clock_type::now()};
	sync::metadata header;
	header.insert(groupchat_message_id, chat_msg);
	auto msg_id = sync::util::create_object_id();

	// lock mutex for send_data_change too to make sure the insert after it is always done before events come in
	std::unique_lock l{mutex_};
	auto handle = send_data_change(msg_id, std::move(header));

	msg_data data{chat_msg, my_key_id_, handle->internal_id()};
	auto change = messages_.insert(msg_id, data, msg_state::pending);

	return message{
		msg,
		my_key_id_,
		msg_id,
		chat_msg.sender_time,
		change.new_index,
		change.state};
}

std::deque<message> channel::messages(message_search ms) const {
	std::unique_lock l{mutex_};
	return messages_.get(ms);
}

chat_id channel::id() const {
	return chat_id_;
}

}