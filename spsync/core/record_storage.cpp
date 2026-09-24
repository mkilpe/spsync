#include "record_storage.hpp"

#include <utility>

#include <securepath/database/util.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>
#include <spsync/core/data/data_index.hpp>
#include <spsync/core/data/data_state_table.hpp>
#include <spsync/core/database_util.hpp>
#include <securepath/serialisation/vector.hpp>
#include <spsync/core/records/data_change_record.hpp>

#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>

#include <format>
#include <memory>
#include <mutex>
#include <string_view>
#include <unordered_map>
#include <map>
#include <unordered_set>

namespace securepath::sync {
namespace {

std::int64_t const seq_selector_value(1);

void create_object_records(database::connection_ptr db, octet_vector const& tag, data_change_record const& rec) {
	for(auto& obj : rec) {
		auto q = db->prepare(
			"INSERT INTO record_objects(tag, prev_tag, oid, data_ref)"
			" VALUES(:tag, :prev_tag, :oid, :data_ref);");
		q.bind(":tag", tag);
		q.bind(":prev_tag", obj.data.previous_oid_record_tag);
		q.bind(":oid", obj.data.id.value());
		if(obj.data.data && usable_data_descriptor(*obj.data.data)) {
			// every record naming the data shares its row (reference counting by data_id, RD9)
			q.bind(":data_ref", static_cast<std::int64_t>(data_index{db}.reference(*obj.data.data)));
		} else {
			if(obj.data.data) {
				// a server refuses such a record (chain validity); a client that is handed
				// one keeps the record and knows no data for it
				LOG_WARN("record names a data with a descriptor out of bounds, not indexed [tag={}]", to_hex(tag));
			}
			q.bind(":data_ref");
		}
		q.execute();
	}
}

char const* const create_object_table =
	"CREATE TABLE record_objects("
	"key INTEGER PRIMARY KEY,"
	"tag BLOB,"
	"prev_tag BLOB,"
	"oid BLOB,"
	"data_ref INTEGER);";

/// true for a table from before RDS 2: data_ref was unique there, now records share data rows
bool has_unique_data_ref(database::connection& db) {
	auto q = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'record_objects';");
	auto res = q.execute();
	return res && res.value<std::string>(0).value_or("").find("data_ref INTEGER UNIQUE") != std::string::npos;
}

void create_or_upgrade_object_table(database::connection& db) {
	if(!db.has_table("record_objects")) {
		db.prepare(create_object_table).execute();
	} else if(has_unique_data_ref(db)) {
		// sqlite cannot drop a constraint: rebuild the table
		database::transaction tact(db);
		db.prepare("ALTER TABLE record_objects RENAME TO record_objects_old;").execute();
		db.prepare(create_object_table).execute();
		db.prepare("INSERT INTO record_objects(key, tag, prev_tag, oid, data_ref)"
			" SELECT key, tag, prev_tag, oid, data_ref FROM record_objects_old;").execute();
		db.prepare("DROP TABLE record_objects_old;").execute();
	}
	db.prepare("CREATE INDEX IF NOT EXISTS record_objects_data_ref ON record_objects(data_ref);").execute();
}

class database_record : public record_interface {
public:
	database_record(database::connection_ptr db, std::int64_t record_key, record_tag tag
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

			// the object rows are keyed by the tag: drop them before the tag changes
			remove_object_records();
			update_record(rec);

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

	void set_assignment(octet_vector const& env, octet_vector const& origin, sequence_number origin_seq) override {
		auto q = db_->prepare("UPDATE record SET envelope = :e, origin = :o, origin_seq = :os WHERE key = :k;");
		q.bind(":e", env);
		if(origin.empty()) {
			q.bind(":o");
			q.bind(":os");
		} else {
			q.bind(":o", origin);
			q.bind(":os", static_cast<std::uint64_t>(origin_seq.value));
		}
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
	std::int64_t const record_key_;
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
		origin: public key id of the origin server of the stored assignment (plan 4.4)
		origin_seq: the origin server's sequence for the record (plan 4.4)
		unique_seq_selector: used to make combination state == insync and seq unique

	database table 'record_objects':
		key: arbitrary table index as integer (primary key)
		tag: the record tag this row belongs to
		prev_tag: the record tag for previous change to the same object
		oid: object id as blob
		data_ref: row of the record data table (data_state_table) when the change has data,
			shared by every change naming the same data_id
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
				"origin BLOB,"
				"origin_seq INTEGER,"
				"unique_seq_selector INTEGER DEFAULT NULL,"
				"UNIQUE(seq, unique_seq_selector));").execute();
		}
		create_or_upgrade_object_table(*db);
		// the object rows point into the record data table: it comes with the storage
		data_state_table{db};
		if(!db->has_table("sync_state")) {
			db->prepare("CREATE TABLE sync_state("
				"key INTEGER PRIMARY KEY CHECK(key = 1),"
				"cursor_owner BLOB,"
				"max_record_size INTEGER,"
				"chunk_size INTEGER,"
				"data_endpoints BLOB,"
				"kept_data_versions INTEGER);").execute();
		} else {
			if(!has_column(*db, "sync_state", "data_endpoints")) {
				// a database from before RDS 5
				db->prepare("ALTER TABLE sync_state ADD COLUMN data_endpoints BLOB;").execute();
			}
			if(!has_column(*db, "sync_state", "kept_data_versions")) {
				// from before the retention policy (RDS 9): not known until the server tells
				db->prepare("ALTER TABLE sync_state ADD COLUMN kept_data_versions INTEGER;").execute();
			}
		}
	}

	// construct record handle from query (SELECT key, tag, seq, hash, parent_hash, state, ... )
	record_handle construct_record(std::int64_t key, database::query const& q) {
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
			// the rowid is a plain integer: not an offset unsigned like the sequences
			auto key = q.value<std::int64_t>(0);
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
		std::int64_t key{};
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
			auto key = res.value<std::int64_t>(0);
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

	record_handle load_by_key(std::int64_t key) {
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
		/// row of the record data table when the change names a data
		std::optional<std::uint64_t> data_ref;
	};

	/// one record of an object's previous-record chain
	struct object_version {
		record_tag tag;
		record_tag prev_tag;
		std::uint64_t seq{};
		std::optional<std::uint64_t> data_ref;
	};

	/// the newest in sync record per object id with its previous-record link
	std::vector<object_head_row> collect_object_heads() {
		// sqlite: bare columns beside max() come from the matching row
		auto q = db->prepare(
			"SELECT record_objects.oid, record_objects.tag, record_objects.prev_tag, max(record.seq), record_objects.data_ref"
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
				, res.value<std::uint64_t>(3).value_or(0)
				, data_ref_of(res.value<std::int64_t>(4))});
		}
		return rows;
	}

	static std::optional<std::uint64_t> data_ref_of(std::optional<std::int64_t> const& column) {
		return column ? std::optional<std::uint64_t>{static_cast<std::uint64_t>(*column)} : std::nullopt;
	}

	/// the in sync record with the given tag as a version of the object
	std::optional<object_version> find_object_version(octet_vector const& oid, record_tag const& tag) {
		auto q = db->prepare(
			"SELECT record.seq, record_objects.prev_tag, record_objects.data_ref FROM record_objects"
			" JOIN record ON record.tag = record_objects.tag"
			" WHERE record_objects.tag = :t AND record_objects.oid = :o AND record.state = :state;");
		q.bind(":t", tag);
		q.bind(":o", oid);
		q.bind(":state", std::to_underlying(record_state::in_sync));
		std::optional<object_version> ret;
		if(auto res = q.execute()) {
			ret = object_version{tag, res.value<octet_vector>(1).value_or(octet_vector{})
				, res.value<std::uint64_t>(0).value_or(0), data_ref_of(res.value<std::int64_t>(2))};
		} else {
			LOG_WARN("object chain dangles [oid={}, missing tag={}]", to_hex(oid), to_hex(tag));
		}
		return ret;
	}

	/**
	 * The in sync records of one object, from its newest one along the previous-record
	 * links: its versions, newest first. Every object is walked on its own - a record
	 * that changes several objects continues differently for each of them.
	 */
	/// the rows of the data the retention policy lets go at a cut, see superseded_data_below
	std::vector<data_state_row> superseded_rows(sequence_number below, std::uint32_t kept_versions);

	std::vector<object_version> object_versions(object_head_row const& head) {
		std::vector<object_version> ret;
		std::unordered_set<record_tag> visited;
		std::optional<object_version> version = object_version{head.tag, head.prev_tag, head.seq, head.data_ref};
		while(version && visited.insert(version->tag).second) {
			ret.push_back(*version);
			auto const prev = version->prev_tag;
			version = prev.empty() ? std::nullopt : find_object_version(head.oid, prev);
		}
		return ret;
	}

	/// the tags of one object's versions below the cut; seen keeps a record of several
	/// objects from being listed twice
	void collect_object_chain(object_head_row const& head, sequence_number below
		, std::unordered_set<record_tag>& seen, std::vector<record_tag>& ret) {
		for(auto const& version : object_versions(head)) {
			if(sequence_number{version.seq} < below && seen.insert(version.tag).second) {
				ret.push_back(version.tag);
			}
		}
	}

	// drop the cache entry of a deleted row; a still live handle is flipped to invalid
	void invalidate_handle(std::int64_t key) {
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

sequence_number record_storage::first_missing_sequence(sequence_number from) const {
	auto const received = " state IN (" + std::to_string(std::to_underlying(record_state::in_sync)) + ","
		+ std::to_string(std::to_underlying(record_state::acked)) + ","
		+ std::to_string(std::to_underlying(record_state::pending_sync)) + ")";
	auto highest = impl_->db->prepare("SELECT max(seq) FROM record WHERE" + received + ";");
	sequence_number const top{highest.execute().value<std::uint64_t>(0).value_or(0)};
	sequence_number ret;
	if(from.is_valid() && from <= top) {
		auto at_from = impl_->db->prepare("SELECT count(*) FROM record WHERE seq = :from AND" + received + ";");
		at_from.bind(":from", from.value);
		// a count is a plain integer (sequences are stored with the unsigned offset)
		if(at_from.execute().value<std::int64_t>(0).value_or(0) == 0) {
			ret = from;
		} else {
			// the first received record (at or above from) whose successor is missing
			auto q = impl_->db->prepare("SELECT min(r.seq) + 1 FROM record r WHERE r.seq >= :from AND r.seq < :top AND" + received
				+ " AND NOT EXISTS (SELECT 1 FROM record n WHERE n.seq = r.seq + 1 AND n." + received + ");");
			q.bind(":from", from.value);
			q.bind(":top", top.value);
			auto res = q.execute();
			if(res) {
				ret = sequence_number{res.value<std::uint64_t>(0).value_or(0)};
			}
		}
	}
	return ret;
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
				// the sequence assignment belonged to the sequence it no longer holds
				handle->set_assignment({});
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

std::vector<record_handle> record_storage::find_all_of_type(record_type_tag type) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state FROM record"
		" WHERE state = :state AND type = :type ORDER BY seq ASC;");
	q.bind(":state", std::to_underlying(record_state::in_sync));
	q.bind(":type", std::to_underlying(type));

	std::vector<record_handle> ret;
	auto res = q.execute();
	for(; res; res.next()) {
		ret.push_back(impl_->load_record(res));
	}
	return ret;
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

chain_block_id record_storage::last_of_origin(octet_vector const& origin) const {
	auto q = impl_->db->prepare(
		"SELECT seq, hash FROM record WHERE state = :state AND origin = :o ORDER BY origin_seq DESC LIMIT 1;");
	q.bind(":state", std::to_underlying(record_state::in_sync));
	q.bind(":o", origin);
	chain_block_id ret;
	if(auto res = q.execute()) {
		ret = chain_block_id{sequence_number{res.value<std::uint64_t>(0).value_or(0)}, res.value<octet_vector>(1).value_or(octet_vector{})};
	}
	return ret;
}

std::vector<octet_vector> record_storage::find_origin_assignments(octet_vector const& origin,
	sequence_number from, sequence_number to, std::size_t max) const {
	auto q = impl_->db->prepare(
		"SELECT envelope FROM record WHERE state = :state AND origin = :o"
		" AND origin_seq >= :from AND origin_seq <= :to ORDER BY origin_seq ASC LIMIT :max;");
	q.bind(":state", std::to_underlying(record_state::in_sync));
	q.bind(":o", origin);
	q.bind(":from", static_cast<std::uint64_t>(from.value));
	q.bind(":to", static_cast<std::uint64_t>(to.value));
	// LIMIT takes the plain value: the unsigned bind offsets values for ordered columns
	q.bind(":max", static_cast<std::int64_t>(std::min<std::size_t>(max
		, std::numeric_limits<std::int64_t>::max())));

	std::vector<octet_vector> ret;
	auto res = q.execute();
	for(; res; res.next()) {
		auto env = res.value<octet_vector>(0);
		if(env) {
			ret.push_back(std::move(*env));
		}
	}
	return ret;
}

octet_vector record_storage::cursor_owner() const {
	auto q = impl_->db->prepare("SELECT cursor_owner FROM sync_state WHERE key = 1;");
	octet_vector ret;
	auto res = q.execute();
	if(res) {
		ret = res.value<octet_vector>(0).value_or(octet_vector{});
	}
	return ret;
}

void record_storage::set_cursor_owner(octet_vector const& owner) {
	auto q = impl_->db->prepare(
		"INSERT INTO sync_state(key, cursor_owner) VALUES(1, :o)"
		" ON CONFLICT(key) DO UPDATE SET cursor_owner = excluded.cursor_owner;");
	q.bind(":o", owner);
	q.execute();
}

storage_limits record_storage::limits() const {
	auto q = impl_->db->prepare("SELECT max_record_size, chunk_size, kept_data_versions FROM sync_state WHERE key = 1;");
	storage_limits ret;
	if(auto res = q.execute()) {
		ret.max_record_size = static_cast<std::uint32_t>(res.value<std::int64_t>(0).value_or(0));
		ret.chunk_size = static_cast<std::uint32_t>(res.value<std::int64_t>(1).value_or(0));
		ret.kept_data_versions = static_cast<std::uint32_t>(res.value<std::int64_t>(2).value_or(0));
	}
	return ret;
}

void record_storage::set_limits(storage_limits const& l) {
	auto q = impl_->db->prepare(
		"INSERT INTO sync_state(key, max_record_size, chunk_size, kept_data_versions) VALUES(1, :m, :c, :k)"
		" ON CONFLICT(key) DO UPDATE SET max_record_size = excluded.max_record_size, chunk_size = excluded.chunk_size"
		", kept_data_versions = excluded.kept_data_versions;");
	q.bind(":m", static_cast<std::int64_t>(l.max_record_size));
	q.bind(":c", static_cast<std::int64_t>(l.chunk_size));
	q.bind(":k", static_cast<std::int64_t>(l.kept_data_versions));
	q.execute();
}

std::vector<data_state_row> record_storage::impl::superseded_rows(sequence_number below, std::uint32_t kept_versions) {
	std::vector<data_state_row> ret;
	if(kept_versions != 0 && kept_versions != keep_all_data_versions) {
		// row of the record data table -> references by versions beyond the kept ones
		std::map<std::uint64_t, std::uint64_t> superseded;
		for(auto const& head : collect_object_heads()) {
			std::uint64_t carrying = 0;
			for(auto const& version : object_versions(head)) {
				if(version.data_ref && sequence_number{version.seq} < below && ++carrying > kept_versions) {
					++superseded[*version.data_ref];
				}
			}
		}
		// somebody else naming the data keeps it
		ret = data_index{db}.only_referenced_by(superseded);
	}
	return ret;
}

std::vector<data_id> record_storage::superseded_data_below(sequence_number below, std::uint32_t kept_versions) const {
	std::vector<data_id> ret;
	for(auto const& row : impl_->superseded_rows(below, kept_versions)) {
		ret.push_back(row.descriptor.manifest_digest);
	}
	return ret;
}

std::vector<data_id> record_storage::prune_superseded_data(sequence_number below, std::uint32_t kept_versions) {
	return data_index{impl_->db}.prune(impl_->superseded_rows(below, kept_versions));
}

std::vector<data_id> record_storage::unreferenced_data() const {
	return data_index{impl_->db}.unreferenced();
}

std::vector<data_id> record_storage::remove_unreferenced_data() {
	return data_index{impl_->db}.remove_unreferenced();
}

std::vector<data_endpoint> record_storage::data_endpoints() const {
	auto q = impl_->db->prepare("SELECT data_endpoints FROM sync_state WHERE key = 1;");
	std::vector<data_endpoint> ret;
	auto res = q.execute();
	if(res && res.value<octet_vector>(0)) {
		ret = database::extract_column_type<std::vector<data_endpoint>>(res, 0);
	}
	return ret;
}

void record_storage::set_data_endpoints(std::vector<data_endpoint> const& endpoints) {
	auto q = impl_->db->prepare(
		"INSERT INTO sync_state(key, data_endpoints) VALUES(1, :e)"
		" ON CONFLICT(key) DO UPDATE SET data_endpoints = excluded.data_endpoints;");
	q.bind(":e", serialisation::asn_der_serialise(endpoints));
	q.execute();
}

std::uint64_t record_storage::data_reference_count(std::uint64_t data_ref) const {
	return data_index{impl_->db}.reference_count(data_ref);
}

std::vector<data_id> record_storage::confirmed_data_in_state(record_data_state state) const {
	return data_index{impl_->db}.confirmed_in_state(state);
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
