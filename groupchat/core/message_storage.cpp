#include "message_storage.hpp"

#include <securepath/serialisation/sequence.hpp>
#include <spsync/client/record_util.hpp>

#include <algorithm>

namespace securepath::groupchat {

/*
	We are mapping record storage structure to messages structure.
	Single record can have multiple changes, and hence multiple messages
	can have the same record sequence number (and internal id) but
	the assigned key (index) is unique and fully ordered.

*/

message_storage::message_storage(database::connection_ptr db)
: db_(db)
{
	if(!db->has_table("sync_msg")) {
		LOG_TRACE("creating sync_msg table to db");
		std::string prepare_str =
			"CREATE TABLE sync_msg("
				"key INTEGER PRIMARY KEY,"
				"id BLOB UNIQUE,"
				"data BLOB,"
				"stime INTEGER,"
				"seq INTEGER);";
		db->prepare(prepare_str).execute();
	}
	if(!db->has_table("sync_pending_msg")) {
		LOG_TRACE("creating sync_pending_msg table to db");
		std::string prepare_str =
			"CREATE TABLE sync_pending_msg("
				"key INTEGER PRIMARY KEY,"
				"id BLOB UNIQUE,"
				"data BLOB,"
				"stime INTEGER,"
				"iid INTEGER);";
		db->prepare(prepare_str).execute();
	}

	auto q = db_->prepare("SELECT max(key) FROM sync_msg;");
	auto res = q.execute();
	if(res) {
		sync_max_index_ = res.value<std::int64_t>(0).value_or(0);
	}
	LOG_TRACE("message_storage, max sync key = {}", sync_max_index_);
}

msg_change message_storage::insert(message_id const& id, msg_data const& md, msg_state state) {
	LOG_TRACE("message_storage::insert [id={}, md.seq={}, md.iid={}, state={}]", id, md.seq, md.iid, int(state));

	std::string prep;
	std::int64_t index_base = 0;
	std::int64_t old_index = 0;

	database::transaction t{*db_};

	if(state == msg_state::in_sync) {
		old_index = update_pending(id);
		prep = "INSERT INTO sync_msg(id, data, stime, seq) VALUES(:id, :data, :stime, :seq)";
	} else {
		// a message that is still pending at a restart is reconciled again: keep the entry
		auto existing = db_->prepare("SELECT key FROM sync_pending_msg WHERE id = :id;");
		existing.bind(":id", id.value());
		if(auto res = existing.execute()) {
			return msg_change{sync_max_index_ + res.value<std::int64_t>(0).value(), 0, id, state};
		}
		prep = "INSERT INTO sync_pending_msg(id, data, stime, iid) VALUES(:id, :data, :stime, :iid)";
		index_base = sync_max_index_;
	}
	auto q = db_->prepare(prep);
	q.bind(":id", id.value());
	q.bind(":data", serialisation::asn_der_serialise(md));
	// microseconds: messages sent in quick succession must not tie on the sender time,
	// the time order is the order the sender meant (the chain order can differ after a rebase)
	q.bind(":stime", static_cast<std::int64_t>(
		std::chrono::duration_cast<std::chrono::microseconds>(md.sender_time.time_since_epoch()).count()));
	if(state == msg_state::in_sync) {
		q.bind(":seq", md.seq.value);
	} else {
		q.bind(":iid", md.iid);
	}
	q.execute();

	if(state == msg_state::in_sync)  {
		++sync_max_index_;
	}
	std::int64_t index = index_base+q.last_inserted_row_id();
	return msg_change{index, old_index, id, state};
}

std::int64_t message_storage::update_pending(message_id const& id) {
	std::int64_t pindex = 0;

	// find if there is pending message
	{
		auto q = db_->prepare("SELECT key FROM sync_pending_msg WHERE id = :id;");
		q.bind(":id", id.value());
		auto res = q.execute();
		if(!res) {
			return 0;
		}
		pindex = res.value<std::int64_t>(0).value();
	}

	// remove the msg from pending table
	{
		auto q = db_->prepare("DELETE FROM sync_pending_msg WHERE key = :i");
		q.bind(":i", pindex);
		q.execute();
	}

	// update indexes in pending table
	{
		auto q = db_->prepare("UPDATE sync_pending_msg SET key = key-1 WHERE key > :i");
		q.bind(":i", pindex);
		q.execute();
	}

	return sync_max_index_+pindex;
}

static bool is_time_order(msg_order order) {
	return order == msg_order::time_ascending || order == msg_order::time_descending;
}

static std::string make_prep_string(std::string const& table, message_search s) {
	std::string prep = "SELECT key, id, data FROM " + table;
	if(is_time_order(s.order)) {
		// time orders honour only max_count; chunking with start_index stays index based
		char const* dir = s.order == msg_order::time_ascending ? "ASC" : "DESC";
		prep += std::string(" ORDER BY stime ") + dir + ", key " + dir;
		if(s.max_count) {
			prep += " LIMIT " + std::to_string(s.max_count);
		}
		return prep;
	}
	if(s.order == msg_order::index_ascending) {
		if(s.start_index) {
			prep += " WHERE key >= " + std::to_string(s.start_index);
		}
		prep += " ORDER BY key ASC";
	} else {
		if(s.start_index) {
			prep += " WHERE key <= " + std::to_string(s.start_index);
		}
		prep += " ORDER BY key DESC";
	}
	if(s.max_count) {
		prep += " LIMIT " + std::to_string(s.max_count);
	}
	return prep;
}

void message_storage::get_in_sync(message_search s, std::deque<message>& ret) const {
	auto q = db_->prepare(make_prep_string("sync_msg", s));
	auto res = q.execute();
	for(; res; res.next()) {
		std::int64_t index = res.value<std::int64_t>(0).value();
		octet_vector id = res.value<octet_vector>(1).value();
		auto md = serialisation::asn_der_deserialise<msg_data>(res.value<octet_vector>(2).value());
		ret.push_back(message{md.message, user_id{md.sender}, message_id{id}, md.sender_time, index, msg_state::in_sync});
	}
}

void message_storage::get_pending(message_search s, std::deque<message>& ret) const {
	if(s.start_index && !is_time_order(s.order)) {
		s.start_index -= sync_max_index_;
	}
	auto q = db_->prepare(make_prep_string("sync_pending_msg", s));
	auto res = q.execute();
	for(; res; res.next()) {
		std::int64_t index = res.value<std::int64_t>(0).value();
		octet_vector id = res.value<octet_vector>(1).value();
		auto md = serialisation::asn_der_deserialise<msg_data>(res.value<octet_vector>(2).value());
		ret.push_back(message{md.message, user_id{md.sender}, message_id{id}, md.sender_time, sync_max_index_+index, msg_state::pending});
	}
}

std::deque<message> message_storage::get(message_search s) const {
	if(is_time_order(s.order)) {
		return get_by_time(s);
	}
	std::deque<message> ret;

	if(s.order == msg_order::index_ascending) {
		// see if the start index is in the sync messages
		if(!s.start_index || s.start_index <= sync_max_index_) {
			get_in_sync(s, ret);
			s.start_index = 0;
		}
	} else {
		// see if the start index is in the pending messages
		if(!s.start_index || s.start_index > sync_max_index_) {
			get_pending(s, ret);
			s.start_index = 0;
		}
	}
	if(!s.max_count || ret.size() < s.max_count) {
		if(s.max_count) {
			s.max_count -= ret.size();
		}
		if(s.order == msg_order::index_ascending) {
			get_pending(s, ret);
		} else {
			get_in_sync(s, ret);
		}
	}
	return ret;
}

std::deque<message> message_storage::get_by_time(message_search s) const {
	// take the top max_count of each table by sender time and merge them in memory
	s.start_index = 0;
	std::deque<message> ret;
	get_in_sync(s, ret);
	get_pending(s, ret);
	bool const ascending = s.order == msg_order::time_ascending;
	std::ranges::sort(ret, [ascending](message const& l, message const& r) {
			auto lt = std::tie(l.sender_time, l.index);
			auto rt = std::tie(r.sender_time, r.index);
			return ascending ? lt < rt : rt < lt;
		});
	if(s.max_count && ret.size() > s.max_count) {
		ret.resize(s.max_count);
	}
	return ret;
}

sync::sequence_number message_storage::latest_sequence() const {
	auto q = db_->prepare("SELECT max(seq) FROM sync_msg;");
	auto res = q.execute();
	return sync::sequence_number{res ? res.value<std::uint64_t>(0).value_or(0) : 0};
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
	auto m_last = messages.latest_sequence();
	auto r_last = records.last_block().sequence;

	LOG_TRACE("sync_message_storage [m_last={}, r_last={}]", m_last, r_last);

	++m_last; // the m_last seq we already have
	for(; m_last <= r_last; ++m_last) {
		auto handle = records.find(m_last);
		if(handle && handle->type() == sync::record_type_tag::data_change_record_tag) {
			std::deque<sync::single_data_change> res;
			error err = extract_single_data_changes(keys, handle, res);
			if(!err) {
				handle_messages(messages, res, msg_state::in_sync);
			}
		}
	}
	for(auto h = records.find_first_pending_commit(); h; h = records.find_next_pending_commit(h)) {
		if(h->type() == sync::record_type_tag::data_change_record_tag) {
			std::deque<sync::single_data_change> res;
			error err = extract_single_data_changes(keys, h, res);
			if(!err) {
				handle_messages(messages, res, msg_state::pending);
			}
		}
	}
}

}
