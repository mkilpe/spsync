#include "record_storage.hpp"

#include <utility>

#include <securepath/database/util.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>
#include <spsync/core/records/data_change_record.hpp>

#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <format>
#include <memory>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace securepath::sync {
namespace {

std::int64_t const seq_selector_value(1);

/// acked and in_sync both carry a server assigned sequence; they share the unique
/// sequence selector so no two such records can claim the same sequence
bool is_server_confirmed(record_state state) {
	return state == record_state::in_sync || state == record_state::acked;
}

void create_object_records(database::connection_ptr db, octet_vector const& tag, data_change_record const& rec) {
	for(auto& obj : rec) {
		auto q = db->prepare(
			"INSERT INTO record_objects(tag, prev_tag, oid, data_ref)"
			" VALUES(:tag, :prev_tag, :oid, :data_ref);");
		q.bind(":tag", tag);
		q.bind(":prev_tag", obj.data.previous_oid_record_tag);
		q.bind(":oid", obj.data.id.value());
		q.bind(":data_ref");
		q.execute();
	}
}

class database_record : public record_interface {
public:
	database_record(database::connection_ptr db, std::uint64_t record_key, record_tag tag
		, octet_vector parent_hash, chain_block_id id, record_state state)
	: db_(db)
	, record_key_(record_key)
	, tag_(std::move(tag))
	, parent_hash_(std::move(parent_hash))
	, block_id_(std::move(id))
	, state_(state)
	{}

	chain_block_id block_id() const override {
		std::unique_lock lock{mutex_};
		return block_id_;
	}

	record_tag tag() const override {
		std::unique_lock lock{mutex_};
		return tag_;
	}

	octet_vector parent_block_hash() const override {
		std::unique_lock lock{mutex_};
		return parent_hash_;
	}

	record_state state() const override {
		std::unique_lock lock{mutex_};
		return state_;
	}

	void set_state(record_state state, chain_block_id bid, octet_vector parent_block_hash) override {
		std::unique_lock lock{mutex_};

		if(bid.is_valid()) {
			//update state in database
			auto q = db_->prepare("UPDATE record SET state = :state, seq = :seq, hash = :hash, parent_hash = :parent_hash, unique_seq_selector = :useq WHERE key = :k;");
			q.bind(":state", std::to_underlying(state));
			q.bind(":seq", bid.sequence.value);
			q.bind(":hash", bid.hash);
			q.bind(":parent_hash", parent_block_hash);
			if(is_server_confirmed(state)) {
				q.bind(":useq", seq_selector_value);
			} else {
				q.bind(":useq");
			}
			q.bind(":k", record_key_);
			q.execute();

			block_id_ = std::move(bid);
			parent_hash_ = std::move(parent_block_hash);
		} else {
			//update just the state in database
			auto q = db_->prepare("UPDATE record SET state = :state, unique_seq_selector = :useq WHERE key = :k;");
			q.bind(":state", std::to_underlying(state));
			if(is_server_confirmed(state)) {
				q.bind(":useq", seq_selector_value);
			} else {
				q.bind(":useq");
			}
			q.bind(":k", record_key_);
			q.execute();

		}
		state_ = state;
	}

	chain_block record() const override {
		auto q = db_->prepare("SELECT record FROM record WHERE key = :k;");
		q.bind(":k", record_key_);
		auto res = q.execute();

		if(!res) {
			throw make_error(securepath::errc::invalid_data, "failed to query record chain block from database");
		}

		return database::extract_column_type<chain_block>(res, 0);
	}

	void set_record(chain_block const& rec) override {
		std::unique_lock lock{mutex_};

		if(is_server_confirmed(state_)) {
			throw make_error(sync::errc::constraint_violation, "trying to set record data for in sync record");
		}

		{
			database::transaction tact(*db_);

			update_record(rec);
			remove_object_records();

			rec.deserialise_record([&rec, this](auto const& r)
				{
					if constexpr(std::is_same_v<std::decay_t<decltype(r)>, data_change_record>) {
						create_object_records(db_, rec.tag(), r);
					}
				});
		}
	}

	record_internal_id internal_id() const override {
		return record_key_;
	}

	void set_assignment(octet_vector const& env) override {
		auto q = db_->prepare("UPDATE record SET envelope = :e WHERE key = :k;");
		q.bind(":e", env);
		q.bind(":k", record_key_);
		q.execute();
	}

	octet_vector assignment() const override {
		auto q = db_->prepare("SELECT envelope FROM record WHERE key = :k;");
		q.bind(":k", record_key_);
		auto res = q.execute();
		octet_vector ret;
		if(res) {
			ret = res.value<octet_vector>(0).value_or(octet_vector{});
		}
		return ret;
	}

	void update_record(chain_block const& rec) {
		LOG_TRACE("updating record to storage {} [bid={}, parent_h={}]", to_hex(rec.tag()), rec.id(), to_hex(rec.parent_hash()));

		auto q = db_->prepare(
			"UPDATE record SET tag = :tag, seq = :seq, hash = :hash, parent_hash = :parent_hash,"
			" record = :record, unique_seq_selector = :useq WHERE key = :k;");

		q.bind(":tag", rec.tag());
		if(!rec.parent_hash().empty()) {
			q.bind(":parent_hash", rec.parent_hash());
		} else {
			q.bind(":parent_hash");
		}
		q.bind(":seq", rec.sequence().value);
		q.bind(":hash", rec.hash());
		q.bind(":record", serialisation::asn_der_serialise(rec));
		q.bind(":useq");
		q.bind(":k", record_key_);

		q.execute();

		tag_ = rec.tag();
		parent_hash_ = rec.parent_hash();
		block_id_ = rec.id();
	}

	void remove_object_records() {
		auto q = db_->prepare("DELETE FROM record_objects WHERE tag = :tag;");
		q.bind(":tag", tag_);
		q.execute();
	}

	record_type_tag type() const override {
		auto q = db_->prepare("SELECT type FROM record WHERE key = :k;");
		q.bind(":k", record_key_);
		auto res = q.execute();

		std::int64_t type = 0;
		if(!res || !res.value(0, type)) {
			throw make_error(securepath::errc::invalid_data, "failed to query record type from database");
		}
		return record_type_tag(type);
	}

private:
	mutable std::mutex mutex_;
	database::connection_ptr db_;

	// -- cached data --
	std::uint64_t const record_key_;
	record_tag tag_;
	octet_vector parent_hash_;
	chain_block_id block_id_;
	record_state state_;
};

}

/*
	database table 'record':
		key: arbitrary table index as integer (primary key)
		tag: record tag as blob
		seq: sequence as integer, this is the  server assigned sequence if state is in_sync, otherwise a prediction
		hash: hash of the chain_block, either as returned by server or predicted
		parent_hash: hash of the parent chain block, this is only set after server returns the committed chain block
		state: record state as integer, this is the record_state enum in record_interface.hpp
		record: serialised chain_block as blob
		type: type of the record
		unique_seq_selector: used to make combination state == insync and seq unique

	database table 'record_objects':
		key: arbitrary table index as integer (primary key)
		tag: the record tag this row belongs to
		prev_tag: the record tag for previous change to the same object
		oid: object id as blob
		data_ref: unique id to record data database table as integer
*/

struct record_storage::impl {
	impl(database::connection_ptr conn)
	: db(conn)
	{
		if(!db->has_table("record")) {
			db->prepare("CREATE TABLE record("
				"key INTEGER PRIMARY KEY,"
				"tag BLOB UNIQUE,"
				"seq INTEGER,"
				"hash BLOB UNIQUE,"
				"parent_hash BLOB,"
				"state INTEGER,"
				"record BLOB,"
				"type INTEGER, "
				"op_id BLOB UNIQUE,"
				"envelope BLOB,"
				"unique_seq_selector INTEGER DEFAULT NULL,"
				"UNIQUE(seq, unique_seq_selector));").execute();
		}
		if(!db->has_table("record_objects")) {
			db->prepare("CREATE TABLE record_objects("
				"key INTEGER PRIMARY KEY,"
				"tag BLOB,"
				"prev_tag BLOB,"
				"oid BLOB,"
				"data_ref INTEGER UNIQUE);").execute();
		}
	}

	// construct record handle from query (SELECT key, tag, seq, hash, parent_hash, state, ... )
	record_handle construct_record(std::uint64_t key, database::query const& q) {
		auto tag = q.value<octet_vector>(1);
		auto seq = q.value<std::uint64_t>(2);
		auto hash = q.value<octet_vector>(3);
		auto parent_hash = q.value<octet_vector>(4);
		auto state = q.value<std::int64_t>(5);

		//check if the data is valid, notice that data_ref might not be set
		if(!tag || !state) {
			LOG_WARN("invalid record storage entry [key={}]", key);
			throw make_error(securepath::errc::invalid_data, "failed to interpret record columns");
		}

		return std::make_shared<database_record>
			( db
			, key
			, std::move(*tag)
			, parent_hash.value_or(octet_vector{})
			, chain_block_id{seq.value_or(0), hash.value_or(octet_vector{})}
			, static_cast<record_state>(*state));
	}

	record_handle load_record(database::query const& q) {
		record_handle result;
		if(q) {
			auto key = q.value<std::uint64_t>(0);
			if(!key) {
				LOG_WARN("invalid record storage entry, no key set");
				throw make_error(securepath::errc::invalid_data, "failed to interpret record key column");
			}

			std::unique_lock lock{mutex};
			auto it = record_handles.find(*key);
			if(it != record_handles.end()) {
				result = it->second.lock();
			}

			if(!result) {
				result = construct_record(*key, q);
				record_handles[*key] = result;
			}
		}

		return result;
	}

	struct truncate_row {
		chain_block block;
		record_state state{record_state::unknown};
		std::uint64_t key{};
	};

	// collect the server sequenced rows (in_sync/acked/pending_sync) with seq compared
	// against the given sequence (seq_compare is a fixed SQL operator, e.g. ">=")
	std::vector<truncate_row> collect_truncation_rows(std::string_view seq_compare, sequence_number seq) {
		auto q = db->prepare(std::format(
			"SELECT key, state, record FROM record WHERE seq {} :seq"
			" AND (state = :s1 OR state = :s2 OR state = :s3) ORDER BY seq ASC;", seq_compare));
		q.bind(":seq", static_cast<std::uint64_t>(seq.value));
		q.bind(":s1", std::to_underlying(record_state::in_sync));
		q.bind(":s2", std::to_underlying(record_state::acked));
		q.bind(":s3", std::to_underlying(record_state::pending_sync));

		std::vector<truncate_row> rows;
		auto res = q.execute();
		for(; res; res.next()) {
			auto key = res.value<std::uint64_t>(0);
			auto state = res.value<std::int64_t>(1);
			if(!key || !state) {
				LOG_WARN("invalid record storage entry while truncating");
				throw make_error(securepath::errc::invalid_data, "failed to interpret record columns");
			}
			rows.push_back({database::extract_column_type<chain_block>(res, 2)
				, static_cast<record_state>(*state), *key});
		}
		return rows;
	}

	record_handle load_by_key(std::uint64_t key) {
		auto q = db->prepare(
			"SELECT key, tag, seq, hash, parent_hash, state FROM record WHERE key = :k;");
		q.bind(":k", key);
		return load_record(q.execute());
	}

	void remove_row(truncate_row const& row) {
		auto objs = db->prepare("DELETE FROM record_objects WHERE tag = :tag;");
		objs.bind(":tag", row.block.tag());
		objs.execute();

		auto rec = db->prepare("DELETE FROM record WHERE key = :k;");
		rec.bind(":k", row.key);
		rec.execute();
	}

	struct object_head_row {
		octet_vector oid;
		record_tag tag;
		record_tag prev_tag;
		std::uint64_t seq{};
	};

	/// the newest in sync record per object id with its previous-record link
	std::vector<object_head_row> collect_object_heads() {
		// sqlite: bare columns beside max() come from the matching row
		auto q = db->prepare(
			"SELECT record_objects.oid, record_objects.tag, record_objects.prev_tag, max(record.seq)"
			" FROM record_objects JOIN record ON record.tag = record_objects.tag"
			" WHERE record.state = :state GROUP BY record_objects.oid;");
		q.bind(":state", std::to_underlying(record_state::in_sync));

		std::vector<object_head_row> rows;
		auto res = q.execute();
		for(; res; res.next()) {
			auto oid = res.value<octet_vector>(0);
			auto tag = res.value<octet_vector>(1);
			if(!oid || !tag) {
				LOG_WARN("invalid record objects entry");
				throw make_error(securepath::errc::invalid_data, "failed to interpret record object columns");
			}
			rows.push_back({std::move(*oid), std::move(*tag)
				, res.value<octet_vector>(2).value_or(octet_vector{})
				, res.value<std::uint64_t>(3).value_or(0)});
		}
		return rows;
	}

	/// walk one object's previous-record chain from its newest record, collecting the
	/// tags below the cut; seen keeps shared chain parts from being walked twice
	void collect_object_chain(object_head_row const& head, sequence_number below
		, std::unordered_set<record_tag>& seen, std::vector<record_tag>& ret) {
		record_tag tag = head.tag;
		record_tag prev = head.prev_tag;
		std::uint64_t seq = head.seq;
		bool walking = true;
		while(walking && !tag.empty() && seen.insert(tag).second) {
			if(sequence_number{seq} < below) {
				ret.push_back(tag);
			}
			if(prev.empty()) {
				walking = false;
			} else {
				auto q = db->prepare(
					"SELECT record.seq, record_objects.prev_tag FROM record_objects"
					" JOIN record ON record.tag = record_objects.tag"
					" WHERE record_objects.tag = :t AND record_objects.oid = :o AND record.state = :state;");
				q.bind(":t", prev);
				q.bind(":o", head.oid);
				q.bind(":state", std::to_underlying(record_state::in_sync));
				auto res = q.execute();
				if(res) {
					tag = prev;
					seq = res.value<std::uint64_t>(0).value_or(0);
					prev = res.value<octet_vector>(1).value_or(octet_vector{});
				} else {
					LOG_WARN("object chain dangles [oid={}, missing tag={}]", to_hex(head.oid), to_hex(prev));
					walking = false;
				}
			}
		}
	}

	// drop the cache entry of a deleted row; a still live handle is flipped to invalid
	void invalidate_handle(std::uint64_t key) {
		record_handle handle;
		{
			std::unique_lock lock{mutex};
			auto it = record_handles.find(key);
			if(it != record_handles.end()) {
				handle = it->second.lock();
				record_handles.erase(it);
			}
		}
		if(handle) {
			handle->set_state(record_state::invalid);
		}
	}

	mutable std::mutex mutex;
	database::connection_ptr db;

	//map record database key to the potential record handle
	std::unordered_map<std::uint64_t, std::weak_ptr<record_interface>> record_handles;
};

record_storage::record_storage(database::connection_ptr conn)
: impl_(std::make_unique<impl>(conn))
{
}

record_storage::~record_storage()
{
}

chain_block_id record_storage::last_block(bool allow_local) const {
	auto q = impl_->db->prepare("SELECT hash, seq FROM record WHERE"
		" seq = (SELECT max(seq) FROM record WHERE state = :state1 OR state = :state2)"
		" AND (state = :state1 OR state = :state2)"
		" ORDER BY key DESC LIMIT 1;");
	q.bind(":state1", std::to_underlying(record_state::in_sync));
	q.bind(":state2", std::to_underlying(allow_local ? record_state::pending_commit : record_state::in_sync));

	chain_block_id id;
	auto res = q.execute();
	if(res) {
		auto hash = res.value<octet_vector>(0);
		auto seq = res.value<std::uint64_t>(1);
		id = chain_block_id{seq.value_or(0), hash.value_or(octet_vector{})};
	}
	return id;
}

record_handle record_storage::find_last(bool allow_local) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record WHERE"
		" seq = (SELECT max(seq) FROM record WHERE state = :state1 OR state = :state2)"
		" AND (state = :state1 OR state = :state2)"
		" ORDER BY key DESC LIMIT 1;");
	q.bind(":state1", std::to_underlying(record_state::in_sync));
	q.bind(":state2", std::to_underlying(allow_local ? record_state::pending_commit : record_state::in_sync));
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_root() const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record WHERE seq = :seq AND state = :state;");
	q.bind(":seq", static_cast<std::uint64_t>(1));
	q.bind(":state", std::to_underlying(record_state::in_sync));
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_last(object_id const& oid) const {
	auto q = impl_->db->prepare(
		"SELECT record.key, record.tag, record.seq, record.hash, record.parent_hash, record.state FROM record, record_objects"
		" WHERE record.tag = record_objects.tag AND record_objects.oid = :o AND"
		" state = :state ORDER BY record.seq DESC LIMIT 1");

	q.bind(":state", std::to_underlying(record_state::in_sync));
	q.bind(":o", oid.value());
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_first(object_id const& oid) const {
	auto q = impl_->db->prepare(
		"SELECT record.key, record.tag, record.seq, record.hash, record.parent_hash, record.state FROM record, record_objects"
		" WHERE record.tag = record_objects.tag AND record_objects.oid = :o AND"
		" state = :state ORDER BY record.seq ASC LIMIT 1");

	q.bind(":state", std::to_underlying(record_state::in_sync));
	q.bind(":o", oid.value());
	return impl_->load_record(q.execute());
}

record_handle record_storage::find(octet_vector const& hash, record_state state) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record"
		" WHERE hash = :h AND state = :state;");
	q.bind(":h", hash);
	q.bind(":state", std::to_underlying(state));
	return impl_->load_record(q.execute());
}

record_handle record_storage::find(sequence_number seq, record_state state) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record WHERE seq = :seq AND state = :state;");
	q.bind(":seq", static_cast<std::uint64_t>(seq.value));
	q.bind(":state", std::to_underlying(state));
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_op_id(octet_vector const& op_id) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record"
		" WHERE op_id = :o;");
	q.bind(":o", op_id);
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_tag(octet_vector const& tag) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record"
		" WHERE tag = :t;");
	q.bind(":t", tag);
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_first_pending_commit() const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record WHERE state = :state"
		" ORDER BY key ASC LIMIT 1");
	q.bind(":state", std::to_underlying(record_state::pending_commit));
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_next_pending_commit(record_handle h) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record WHERE state = :state AND key > :key"
		" ORDER BY key ASC LIMIT 1");
	q.bind(":state", std::to_underlying(record_state::pending_commit));
	q.bind(":key", h->internal_id());
	return impl_->load_record(q.execute());
}

sequence_number record_storage::highest_sequence_number() const {
	auto q = impl_->db->prepare("SELECT max(seq) FROM record WHERE state = :state1 OR state = :state2;");
	q.bind(":state1", std::to_underlying(record_state::in_sync));
	q.bind(":state2", std::to_underlying(record_state::pending_sync));

	sequence_number ret;
	auto res = q.execute();
	if(res) {
		ret = sequence_number{res.value<std::uint64_t>(0).value_or(0)};
	}
	return ret;
}

sequence_number record_storage::last_special_sequence() const {
	auto q = impl_->db->prepare("SELECT max(seq) FROM record WHERE state = :state AND (type = :t1 OR type = :t2);");
	q.bind(":state", std::to_underlying(record_state::in_sync));
	q.bind(":t1", std::to_underlying(user_change_record_tag));
	q.bind(":t2", std::to_underlying(segment_record_tag));

	sequence_number ret;
	auto res = q.execute();
	if(res) {
		ret = sequence_number{res.value<std::uint64_t>(0).value_or(0)};
	}
	return ret;
}

sequence_number record_storage::last_data_add_sequence() const {
	// an add is a data change entry without a previous oid record tag (see create_object_records)
	auto q = impl_->db->prepare(
		"SELECT max(record.seq) FROM record, record_objects"
		" WHERE record.tag = record_objects.tag AND record.state = :state"
		" AND ifnull(length(record_objects.prev_tag), 0) = 0;");
	q.bind(":state", std::to_underlying(record_state::in_sync));

	sequence_number ret;
	auto res = q.execute();
	if(res) {
		ret = sequence_number{res.value<std::uint64_t>(0).value_or(0)};
	}
	return ret;
}

std::vector<chain_block> record_storage::truncate_from(sequence_number first_removed, bool demote_acked) {
	if(!first_removed.is_valid()) {
		throw make_error(sync::errc::constraint_violation, "truncate_from requires a valid sequence number");
	}
	LOG_TRACE("truncating records [first_removed={}, demote_acked={}]", first_removed, demote_acked);

	database::transaction tact(*impl_->db);

	std::vector<chain_block> removed;
	for(auto const& row : impl_->collect_truncation_rows(">=", first_removed)) {
		if(demote_acked && row.state == record_state::acked) {
			if(auto handle = impl_->load_by_key(row.key)) {
				handle->set_state(record_state::pending_commit);
			}
		} else {
			impl_->remove_row(row);
			impl_->invalidate_handle(row.key);
			removed.push_back(row.block);
		}
	}
	return removed;
}

record_handle record_storage::find_last_of_type(record_type_tag type) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record"
		" WHERE state = :state AND type = :type ORDER BY seq DESC LIMIT 1;");
	q.bind(":state", std::to_underlying(record_state::in_sync));
	q.bind(":type", std::to_underlying(type));
	return impl_->load_record(q.execute());
}

std::deque<record_tag> record_storage::tags_in_range(sequence_number first, sequence_number last) const {
	auto q = impl_->db->prepare(
		"SELECT tag FROM record WHERE state = :state AND seq >= :first AND seq <= :last"
		" ORDER BY seq ASC;");
	q.bind(":state", std::to_underlying(record_state::in_sync));
	q.bind(":first", static_cast<std::uint64_t>(first.value));
	q.bind(":last", static_cast<std::uint64_t>(last.value));

	std::deque<record_tag> ret;
	auto res = q.execute();
	for(; res; res.next()) {
		auto tag = res.value<octet_vector>(0);
		if(!tag) {
			LOG_WARN("invalid record storage entry, no tag set");
			throw make_error(securepath::errc::invalid_data, "failed to interpret record tag column");
		}
		ret.push_back(std::move(*tag));
	}
	return ret;
}

std::vector<record_handle> record_storage::find_range(sequence_number first, sequence_number last,
	record_state state, std::size_t max) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record"
		" WHERE state = :state AND seq >= :first AND seq <= :last ORDER BY seq ASC LIMIT :max;");
	q.bind(":state", std::to_underlying(state));
	q.bind(":first", static_cast<std::uint64_t>(first.value));
	q.bind(":last", static_cast<std::uint64_t>(last.value));
	// LIMIT takes the plain value: the unsigned bind offsets values for ordered columns
	q.bind(":max", static_cast<std::int64_t>(std::min<std::size_t>(max
		, std::numeric_limits<std::int64_t>::max())));

	std::vector<record_handle> ret;
	auto res = q.execute();
	for(; res; res.next()) {
		ret.push_back(impl_->load_record(res));
	}
	return ret;
}

std::vector<record_tag> record_storage::object_chain_tags_below(sequence_number below) const {
	std::vector<record_tag> ret;
	std::unordered_set<record_tag> seen;
	for(auto const& head : impl_->collect_object_heads()) {
		impl_->collect_object_chain(head, below, seen, ret);
	}
	return ret;
}

std::vector<chain_block> record_storage::truncate_prefix(sequence_number first_kept,
	std::vector<record_tag> const& retained) {
	if(!first_kept.is_valid()) {
		throw make_error(sync::errc::constraint_violation, "truncate_prefix requires a valid sequence number");
	}
	LOG_TRACE("truncating record prefix [first_kept={}, retained={}]", first_kept, retained.size());

	std::unordered_set<record_tag> const keep{retained.begin(), retained.end()};

	database::transaction tact(*impl_->db);

	std::vector<chain_block> removed;
	for(auto const& row : impl_->collect_truncation_rows("<", first_kept)) {
		if(!keep.contains(row.block.tag())) {
			impl_->remove_row(row);
			impl_->invalidate_handle(row.key);
			removed.push_back(row.block);
		}
	}
	return removed;
}

record_handle record_storage::find_internal(record_internal_id iid) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record"
		" WHERE key = :k;");
	q.bind(":k", iid);
	return impl_->load_record(q.execute());
}

record_handle record_storage::insert_to_db(chain_block const& rec, record_state state, record_type_tag type, octet_vector const& op_id) {
	auto q = impl_->db->prepare(
		"INSERT INTO record(tag, seq, hash, parent_hash, state, record, type, op_id, unique_seq_selector)"
		" VALUES(:tag, :seq, :hash, :parent_hash, :state, :record, :type, :op, :useq);");
	if(op_id.empty()) {
		q.bind(":op");
	} else {
		q.bind(":op", op_id);
	}

	q.bind(":tag", rec.tag());
	if(!rec.parent_hash().empty()) {
		q.bind(":parent_hash", rec.parent_hash());
	} else {
		q.bind(":parent_hash");
	}
	q.bind(":seq", rec.sequence().value);
	q.bind(":hash", rec.hash());
	q.bind(":state", std::to_underlying(state));
	q.bind(":record", serialisation::asn_der_serialise(rec));
	q.bind(":type", std::to_underlying(type));
	if(is_server_confirmed(state)) {
		q.bind(":useq", seq_selector_value);
	} else {
		q.bind(":useq");
	}

	q.execute();

	return find_tag(rec.tag());
}

template<typename RecordType>
record_handle record_storage::create_impl(RecordType const& r, chain_block const& rec, record_state state) {
	database::transaction tact(*impl_->db);
	auto handle = insert_to_db(rec, state, RecordType::tag, r.op_id());
	if(handle) {
		if constexpr(std::is_same_v<std::decay_t<decltype(r)>, data_change_record>) {
			create_object_records(impl_->db, rec.tag(), r);
		}
	}
	return handle;
}

record_handle record_storage::create(chain_block const& rec, record_state state) {
	LOG_TRACE("creating record to storage [tag={}, state={}]", to_hex(rec.tag()), state);
	return rec.deserialise_record<record_handle>([&, this](auto const& r)
		{
			return create_impl(r, rec, state);
		});
}

record_handle record_storage::create(auth_record<data_change_record> const& rec) {
	LOG_TRACE("creating record to storage [tag={}]", to_hex(rec.auth.tag()));

	database::transaction tact(*impl_->db);
	auto handle = insert_to_db(chain_block(rec, rec.record.last_seen_block().sequence + 1), record_state::pending_commit, data_change_record_tag, rec.record.op_id());
	if(handle) {
		create_object_records(impl_->db, rec.auth.tag(), rec.record);
	}
	return handle;
}

}
