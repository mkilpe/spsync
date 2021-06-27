#include "channel.hpp"

#include <securepath/util/conversions.hpp>

namespace securepath::groupchat {

// key for the message metadata
std::string const groupchat_message_id{"message"};

channel::channel(network::context& context, event_system::event_loop& eloop, sync::network_connection& conn, sync::storage_id const& sid)
: engine_output(eloop)
, context_(context)
, database_(database::sqlite::create_sqlite_connection(to_hex(sid) + ".db"))
, storage_(database_)
, enc_keys_(database_)
{
	sync::storage_connection sconn{conn.create_storage_connection(sid, storage_, progress_)};
	engine_ = std::make_unique<sync::sync_engine>(eloop, sconn.input(), enc_keys_, sync::sync_engine_config{""});

	//after this the events will be received
	sconn.attach(*engine_);
}

void channel::on_object_data_changed(sync::record_handle rec) {

}

}