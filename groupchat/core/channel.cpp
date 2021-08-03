#include "channel.hpp"
#include "groupchat.hpp"

#include <spsync/core/records/util.hpp>
#include <spsync/engine/record_verifier.hpp>

#include <securepath/util/conversions.hpp>

namespace securepath::groupchat {

channel::channel(groupchat& parent, network::context& context, event_system::event_loop& eloop, sync::network_connection& conn, chat_id const& cid)
: engine_output(eloop)
, parent_(parent)
, context_(context)
, chat_id_(cid)
, database_(database::sqlite::create_sqlite_connection(to_hex(cid) + ".db"))
, storage_(database_)
, enc_keys_(database_)
{
	sync::storage_connection sconn{conn.create_storage_connection(cid, storage_, progress_)};
	engine_ = std::make_unique<sync::sync_engine>(eloop, sconn.input(), enc_keys_, sync::sync_engine_config{""});

	//after this the events will be received
	sconn.attach(*engine_);
}

void channel::on_object_data_changed(sync::record_handle rec) {
	//t: handle nick etc
	auto record = rec->record();
	auto obj_rec = record.deserialise_to<sync::data_change_record>();

	//t: add some sane helpers to do all the decrypting et al
	auto key = enc_keys_.find(obj_rec.encryption_key());
	if(key) {
		sync::data_change_record_verifier ver(*key, obj_rec, record.auth());
		if(ver.is_authentic() && ver.headers().size() == 1) {
			auto header = ver.headers().front().header;
			auto meta = header.metadata();
			auto opt = meta.find<message_data>(groupchat_message_id);
			if(opt) {
				message m{opt->message, "test", opt->sender_time, rec->block_id().sequence};
				parent_.on_message(1, chat_id_, m);
			} else {
				LOG_WARN("invalid record, no groupchat message found");
			}
		}
	}
}

void channel::create_initial_record() {
	enc_keys_.create_key();
	auto own_key = context_.private_data().my_private_key();
	assert(own_key);
	sync::users initial;
	initial.add(sync::util::user_access{own_key->id(), sync::util::access_type::user_management_access});
	engine_->sync_user_change(initial);
}

message_id channel::send_message(std::string const& msg) {
	message_data chat_msg{msg, clock_type::now()};
	sync::metadata header;
	header.insert(groupchat_message_id, chat_msg);
	auto msg_id = sync::util::create_object_id();
	engine_->sync_object_change(msg_id, std::move(header));
	return msg_id;
}

void channel::change_user(sync::users change) {
	engine_->sync_user_change(std::move(change));
}

}