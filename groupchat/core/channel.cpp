#include "channel.hpp"

namespace securepath::groupchat {

// key for the message metadata
std::string const groupchat_message_id{"message"};

channel::channel(network::context& context, event_system::event_loop& eloop, database::connection_ptr db)
: engine_output(eloop)
, context_(context)
, net_(context_, *this)
, storage_(db)
, enc_keys_(db)
{
}

void channel::on_object_data_changed(sync::record_handle rec) {

}

}