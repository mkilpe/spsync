#include "message_storage.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <spsync/client/record_util.hpp>

namespace securepath::groupchat {

message_storage::message_storage(database::connection_ptr db)
: store_(std::move(db), "sync_msg", "sync_pending_msg")
{
}

msg_change message_storage::insert(message_id const& id, msg_data const& md, msg_state state) {
	auto const change = store_.insert(id, serialisation::asn_der_serialise(md), md.sender_time, md.seq, md.iid
		, state != msg_state::in_sync);
	return msg_change{change.new_index, change.old_index, id, state};
}

bool message_storage::remove_pending(message_id const& id) {
	return store_.remove_pending(id);
}

std::deque<message> message_storage::get(message_search s) const {
	std::deque<message> ret;
	for(auto const& row : store_.get(s)) {
		auto md = serialisation::asn_der_deserialise<msg_data>(row.payload);
		ret.push_back(message{md.message, user_id{md.sender}, row.id, md.sender_time, row.index
			, row.pending ? msg_state::pending : msg_state::in_sync});
	}
	return ret;
}

sync::sequence_number message_storage::latest_sequence() const {
	return store_.latest_sequence();
}

static void handle_messages(message_storage& messages, std::deque<sync::single_data_change> const& changes, msg_state state) {
	for(auto const& c : changes) {
		// check the previous oid for data record to ensure compatibility in the later versions when we do use it
		if(c.data.previous_oid_record_tag.empty()) {
			auto opt = c.header.metadata().find<message_data>(groupchat_message_id);
			if(opt) {
				// insert to message storage
				msg_data data{*opt, c.signer.value_or(crypto::public_key_id{}), c.internal_id, c.seq};
				messages.insert(c.data.id, data, state);
			}
		}
	}
}

void sync_message_storage(message_storage& messages, sync::record_storage const& records, sync::encryption_key_storage const& keys) {
	walk_data_changes(records, keys, messages.latest_sequence(), [&](auto const& changes, bool pending) {
		handle_messages(messages, changes, pending ? msg_state::pending : msg_state::in_sync);
	});
}

}
