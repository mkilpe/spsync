#include "object_store.hpp"

#include <securepath/log/log.hpp>
#include <spsync/client/record_util.hpp>

#include <algorithm>
#include <tuple>

namespace securepath::groupchat {

/*
	We are mapping the record storage structure to a list of objects. A single record can
	carry several changes, so several objects can share a record sequence number (and
	internal id) while the assigned key (index) is unique and fully ordered.

	table '<table>' (confirmed): key INTEGER PRIMARY KEY, id BLOB UNIQUE, data BLOB,
	stime INTEGER (sender time in microseconds), seq INTEGER (record sequence)
	table '<pending table>': key, id, data, stime, iid INTEGER (record internal id)
*/

object_store::object_store(database::connection_ptr db, std::string table, std::string pending_table)
: db_(std::move(db))
, table_(std::move(table))
, pending_table_(std::move(pending_table))
{
	if(!db_->has_table(table_)) {
		LOG_TRACE("creating {} table to db", table_);
		db_->prepare("CREATE TABLE " + table_ + "("
			"key INTEGER PRIMARY KEY,"
			"id BLOB UNIQUE,"
			"data BLOB,"
			"stime INTEGER,"
			"seq INTEGER);").execute();
	}
	if(!db_->has_table(pending_table_)) {
		LOG_TRACE("creating {} table to db", pending_table_);
		db_->prepare("CREATE TABLE " + pending_table_ + "("
			"key INTEGER PRIMARY KEY,"
			"id BLOB UNIQUE,"
			"data BLOB,"
			"stime INTEGER,"
			"iid INTEGER);").execute();
	}

	auto q = db_->prepare("SELECT max(key) FROM " + table_ + ";");
	auto res = q.execute();
	if(res) {
		sync_max_index_ = res.value<std::int64_t>(0).value_or(0);
	}
	LOG_TRACE("object_store {}, max sync key = {}", table_, sync_max_index_);
}

object_change object_store::insert(sync::util::object_id const& id, octet_vector const& payload, time_point sender_time
	, sync::sequence_number seq, sync::record_internal_id iid, bool pending) {
	LOG_TRACE("object_store::insert [table={}, id={}, seq={}, iid={}, pending={}]", table_, id, seq, iid, pending);

	std::string prep;
	std::int64_t index_base = 0;
	std::int64_t old_index = 0;

	database::transaction t{*db_};

	if(!pending) {
		old_index = update_pending(id);
		prep = "INSERT INTO " + table_ + "(id, data, stime, seq) VALUES(:id, :data, :stime, :seq)";
	} else {
		// an object that is still pending at a restart is reconciled again: keep the entry
		auto existing = db_->prepare("SELECT key FROM " + pending_table_ + " WHERE id = :id;");
		existing.bind(":id", id.value());
		if(auto res = existing.execute()) {
			return object_change{sync_max_index_ + res.value<std::int64_t>(0).value(), 0};
		}
		prep = "INSERT INTO " + pending_table_ + "(id, data, stime, iid) VALUES(:id, :data, :stime, :iid)";
		index_base = sync_max_index_;
	}
	auto q = db_->prepare(prep);
	q.bind(":id", id.value());
	q.bind(":data", payload);
	// microseconds: objects sent in quick succession must not tie on the sender time,
	// the time order is the order the sender meant (the chain order can differ after a rebase)
	q.bind(":stime", static_cast<std::int64_t>(
		std::chrono::duration_cast<std::chrono::microseconds>(sender_time.time_since_epoch()).count()));
	if(!pending) {
		q.bind(":seq", seq.value);
	} else {
		q.bind(":iid", iid);
	}
	q.execute();

	if(!pending) {
		++sync_max_index_;
	}
	return object_change{index_base + q.last_inserted_row_id(), old_index};
}

bool object_store::remove_pending(sync::util::object_id const& id) {
	database::transaction t{*db_};
	return update_pending(id) != 0;
}

/// take the object out of the pending list, closing the gap; its index there, 0 when absent
std::int64_t object_store::update_pending(sync::util::object_id const& id) {
	std::int64_t pindex = 0;
	{
		auto q = db_->prepare("SELECT key FROM " + pending_table_ + " WHERE id = :id;");
		q.bind(":id", id.value());
		auto res = q.execute();
		if(!res) {
			return 0;
		}
		pindex = res.value<std::int64_t>(0).value();
	}
	{
		auto q = db_->prepare("DELETE FROM " + pending_table_ + " WHERE key = :i");
		q.bind(":i", pindex);
		q.execute();
	}
	{
		auto q = db_->prepare("UPDATE " + pending_table_ + " SET key = key-1 WHERE key > :i");
		q.bind(":i", pindex);
		q.execute();
	}
	return sync_max_index_ + pindex;
}

namespace {

bool is_time_order(msg_order order) {
	return order == msg_order::time_ascending || order == msg_order::time_descending;
}

/// a row of either table: key, id, data, stime
stored_object row_of(auto const& res, index_type index, bool pending) {
	time_point const stime{std::chrono::microseconds{res.template value<std::int64_t>(3).value_or(0)}};
	return stored_object{sync::util::object_id{res.template value<octet_vector>(1).value()}
		, res.template value<octet_vector>(2).value(), stime, index, pending};
}

/// the two lists merged in sender time order (index within equal times), cut to max_count
std::deque<stored_object> merge_by_time(std::deque<stored_object> confirmed, std::deque<stored_object> pending
	, message_search const& s) {
	std::deque<stored_object> ret = std::move(confirmed);
	ret.insert(ret.end(), pending.begin(), pending.end());
	bool const ascending = s.order == msg_order::time_ascending;
	std::ranges::sort(ret, [ascending](stored_object const& l, stored_object const& r) {
			auto lt = std::tie(l.sender_time, l.index);
			auto rt = std::tie(r.sender_time, r.index);
			return ascending ? lt < rt : rt < lt;
		});
	if(s.max_count && ret.size() > s.max_count) {
		ret.resize(s.max_count);
	}
	return ret;
}

}

std::string object_store::prepare_string(std::string const& table, message_search const& s) const {
	std::string prep = "SELECT key, id, data, stime FROM " + table;
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

void object_store::get_confirmed(message_search s, std::deque<stored_object>& ret) const {
	auto q = db_->prepare(prepare_string(table_, s));
	auto res = q.execute();
	for(; res; res.next()) {
		ret.push_back(row_of(res, res.value<std::int64_t>(0).value(), false));
	}
}

void object_store::get_pending(message_search s, std::deque<stored_object>& ret) const {
	if(s.start_index && !is_time_order(s.order)) {
		s.start_index -= sync_max_index_;
	}
	auto q = db_->prepare(prepare_string(pending_table_, s));
	auto res = q.execute();
	for(; res; res.next()) {
		ret.push_back(row_of(res, sync_max_index_ + res.value<std::int64_t>(0).value(), true));
	}
}

std::deque<stored_object> object_store::get(message_search s) const {
	if(is_time_order(s.order)) {
		return get_by_time(s);
	}
	std::deque<stored_object> ret;
	if(s.order == msg_order::index_ascending) {
		// see if the start index is in the confirmed objects
		if(!s.start_index || s.start_index <= sync_max_index_) {
			get_confirmed(s, ret);
			s.start_index = 0;
		}
	} else {
		// see if the start index is in the pending objects
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
			get_confirmed(s, ret);
		}
	}
	return ret;
}

std::deque<stored_object> object_store::get_by_time(message_search s) const {
	// take the top max_count of each table by sender time and merge them in memory
	s.start_index = 0;
	std::deque<stored_object> confirmed;
	std::deque<stored_object> pending;
	get_confirmed(s, confirmed);
	get_pending(s, pending);
	return merge_by_time(std::move(confirmed), std::move(pending), s);
}

sync::sequence_number object_store::latest_sequence() const {
	auto q = db_->prepare("SELECT max(seq) FROM " + table_ + ";");
	auto res = q.execute();
	return sync::sequence_number{res ? res.value<std::uint64_t>(0).value_or(0) : 0};
}

void walk_data_changes(sync::record_storage const& records, sync::encryption_key_storage const& keys
	, sync::sequence_number after, std::function<void(std::deque<sync::single_data_change> const&, bool pending)> const& fn) {
	auto const last = records.last_block().sequence;
	LOG_TRACE("walk_data_changes [after={}, last={}]", after, last);
	for(auto seq = after + 1; seq <= last; ++seq) {
		auto handle = records.find(seq);
		if(handle && handle->type() == sync::record_type_tag::data_change_record_tag) {
			std::deque<sync::single_data_change> res;
			if(!extract_single_data_changes(keys, handle, res)) {
				fn(res, false);
			}
		}
	}
	for(auto h = records.find_first_pending_commit(); h; h = records.find_next_pending_commit(h)) {
		if(h->type() == sync::record_type_tag::data_change_record_tag) {
			std::deque<sync::single_data_change> res;
			if(!extract_single_data_changes(keys, h, res)) {
				fn(res, true);
			}
		}
	}
}

std::optional<stored_object> object_store::find(sync::util::object_id const& id) const {
	std::optional<stored_object> ret;
	auto q = db_->prepare("SELECT key, id, data, stime FROM " + table_ + " WHERE id = :id;");
	q.bind(":id", id.value());
	if(auto res = q.execute()) {
		ret = row_of(res, res.value<std::int64_t>(0).value(), false);
	} else {
		auto p = db_->prepare("SELECT key, id, data, stime FROM " + pending_table_ + " WHERE id = :id;");
		p.bind(":id", id.value());
		if(auto pres = p.execute()) {
			ret = row_of(pres, sync_max_index_ + pres.value<std::int64_t>(0).value(), true);
		}
	}
	return ret;
}

}
