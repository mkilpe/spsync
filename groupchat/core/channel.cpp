#include "channel.hpp"
#include "groupchat.hpp"

#include <spsync/core/records/util.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <spsync/client/record_util.hpp>

#include <securepath/util/conversions.hpp>
#include <securepath/util/string_util.hpp>

namespace securepath::groupchat {

channel::channel(groupchat& parent, network::context& context, event_system::event_loop& eloop, chat_id const& cid)
: engine_output(eloop)
, parent_(parent)
, context_(context)
, chat_id_(cid)
, progress_(eloop)
, database_()
{
}

void channel::set_name(std::wstring name) {
	name_ = std::move(name);
	//t: update name in db
}

void channel::init(sync::network_connection& conn) {
	database_ = database::sqlite::create_sqlite_connection(to_hex(chat_id_) + ".db");
	storage_ = std::make_unique<sync::record_storage>(database_);
	enc_keys_ = std::make_unique<sync::encryption_key_storage>(database_);

	sync::storage_connection sconn{conn.create_storage_connection(chat_id_, *storage_, progress_)};
	engine_ = std::make_unique<sync::sync_engine>(event_loop(), sconn.input(), *enc_keys_, sync::sync_engine_config{""});
	engine_->set_output(this);

	//after this the events will be received
	sconn.attach(*engine_);

	// key for testing
	sync::encryption_key res;
	res.key_seq = sync::sequence_number{1};
	res.key = to_octet_vector("test key plah plkah plah");
	enc_keys_->insert(res);
}

void channel::on_object_data_changed(sync::record_handle rec) {
	LOG_TRACE("on_object_data_changed");
	assert(engine_);
	//t: handle nick etc

	auto opt_meta = extract_single_object_meta(*enc_keys_, rec);
	if(opt_meta) {
		auto opt = opt_meta->find<message_data>(groupchat_message_id);
		if(opt) {
			message m{opt->message, "test", opt->sender_time, rec->block_id().sequence};
			parent_.on_message(1, chat_id_, m);
		} else {
			LOG_WARN("invalid record, no groupchat message found");
		}
	} else {
		LOG_WARN("invalid record");
	}
}

void channel::on_user_changed(sync::record_handle rec) {
	//t: implement
	parent_.on_change_user(1, chat_id_, sync::users{}, error{});
}

void channel::create_initial_record() {
	assert(engine_);
	//enc_keys_->create_key();

	auto own_key = context_.private_data().my_private_key();
	assert(own_key);
	sync::metadata header;
	header.insert(groupchat_name_id, to_string(name_));
	sync::users initial;
	initial.add(sync::util::user_access{own_key->id(), sync::util::access_type::user_management_access});
	engine_->sync_user_change(initial, std::move(header));
}

message_id channel::send_message(std::string const& msg) {
	assert(engine_);
	message_data chat_msg{msg, clock_type::now()};
	sync::metadata header;
	header.insert(groupchat_message_id, chat_msg);
	auto msg_id = sync::util::create_object_id();
	engine_->sync_object_change(msg_id, std::move(header));
	return msg_id;
}

void channel::change_user(sync::users change) {
	assert(engine_);
	engine_->sync_user_change(std::move(change));
}

}