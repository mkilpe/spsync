#include "record_storage.hpp"

#include <securepath/database/util.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/conversions.hpp>

#include <memory>
#include <mutex>

namespace securepath::sync {
namespace {

class database_record : public record_interface {
public:
	database_record(database::connection_ptr db, std::uint64_t record_key, record_tag tag
		, octet_vector parent_hash, chain_block_id id, record_state state, std::uint64_t data_ref)
	: db_(db)
	, record_key_(record_key)
	, tag_(std::move(tag))
	, parent_hash_(std::move(parent_hash))
	, block_id_(std::move(id))
	, state_(state)
	, data_ref_(data_ref)
	{}

	virtual chain_block_id block_id() const {
		std::unique_lock lock{mutex_};
		return block_id_;
	}

	virtual record_tag tag() const {
		std::unique_lock lock{mutex_};
		return tag_;
	}

	virtual octet_vector parent_block_hash() const {
		std::unique_lock lock{mutex_};
		return parent_hash_;
	}

	virtual record_state state() const {
		std::unique_lock lock{mutex_};
		return state_;
	}

	virtual void set_state(record_state state) {
		std::unique_lock lock{mutex_};

		//update state in database
		auto q = db_->prepare("UPDATE record SET state = :state WHERE key = :k;");
		q.bind(":state", static_cast<std::int64_t>(state));
		q.bind(":k", record_key_);
		q.execute();

		state_ = state;
	}

	virtual void set_in_sync(chain_block_id bid, octet_vector parent_block_hash) {
		std::unique_lock lock{mutex_};

		//update state in database
		auto q = db_->prepare("UPDATE record SET state = :state, seq = :seq, hash = :hash, parent_hash = :parent_hash WHERE key = :k;");
		q.bind(":state", static_cast<std::int64_t>(record_state::in_sync));
		q.bind(":seq", bid.sequence.value);
		q.bind(":hash", bid.hash);
		q.bind(":parent_hash", parent_block_hash);
		q.bind(":k", record_key_);
		q.execute();

		state_ = record_state::in_sync;
		block_id_ = std::move(bid);
		parent_hash_ = std::move(parent_block_hash);
	}

	virtual void set_oid(octet_vector const& oid) {
		//update object id in database
		auto q = db_->prepare("UPDATE record SET oid = :o WHERE key = :k;");
		q.bind(":o", oid);
		q.bind(":k", record_key_);
		q.execute();
	}

	virtual record_data_handle data() {
		//todo: use data_ref_ to load from db
		return nullptr;
	}

	virtual const_record_data_handle data() const {
		//todo: use data_ref_ to load from db
		return nullptr;
	}

	virtual chain_block record() const {
		auto q = db_->prepare("SELECT record FROM record WHERE key = :k;");
		q.bind(":k", record_key_);
		auto res = q.execute();

		if(!res) {
			throw make_error(securepath::errc::invalid_data, "failed to query record chain block from database");
		}

		return database::extract_column_type<chain_block>(res, 0);
	}

private:
	mutable std::mutex mutex_;
	database::connection_ptr db_;

	// -- cached data --
	std::uint64_t record_key_;
	record_tag tag_;
	octet_vector parent_hash_;
	chain_block_id block_id_;
	record_state state_;
	std::uint64_t data_ref_;
};

}

/*
	database table 'record':
		key: arbitrary table index as integer (primary key)
		tag: record tag as blob
		seq: sequence as integer, this is only set after server returns the committed chain block
		hash: hash of the chain_block, this is only set after server returns the committed chain block
		parent_hash: hash of the parent chain block, this is only set after server returns the committed chain block
		oid: object id as blob
		state: record state as integer, this is the record_state enum in record_interface.hpp
		data_ref: unique id to record data database table as integer
		record: serialised chain_block as blob
*/

struct record_storage::impl {
	impl(database::connection_ptr conn)
	: db(conn)
	{
		if(!db->has_table("record")) {
			db->prepare("CREATE TABLE record("
				"key INTEGER PRIMARY KEY,"
				"tag BLOB UNIQUE,"
				"seq INTEGER UNIQUE,"
				"hash BLOB UNIQUE,"
				"parent_hash BLOB UNIQUE,"
				"oid BLOB,"
				"state INTEGER,"
				"data_ref INTEGER,"
				"record BLOB);").execute();
		}
	}

	// construct record handle from query (SELECT key, tag, seq, hash, parent_hash, state, data_ref ... )
	record_handle construct_record(std::uint64_t key, database::query const& q) {
		auto tag = q.value<octet_vector>(1);
		auto seq = q.value<std::uint64_t>(2);
		auto hash = q.value<octet_vector>(3);
		auto parent_hash = q.value<octet_vector>(4);
		auto state = q.value<std::int64_t>(5);
		auto data_ref = q.value<std::uint64_t>(6);

		//check if the data is valid, notice that data_ref might not be set
		if(!tag || !state) {
			LOG_WARN("invalid record storage entry [key=%1%]", key);
			throw make_error(securepath::errc::invalid_data, "failed to interpret record columns");
		}

		return std::make_shared<database_record>
			( db
			, key
			, std::move(*tag)
			, parent_hash.value_or(octet_vector{})
			, chain_block_id{seq.value_or(0), hash.value_or(octet_vector{})}
			, static_cast<record_state>(*state)
			, data_ref.value_or(0));
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

chain_block_id record_storage::last_block() const {
	auto q = impl_->db->prepare("SELECT hash, seq FROM record WHERE"
		" seq = (SELECT max(seq) FROM record WHERE state = :state);");
	q.bind(":state", static_cast<std::int64_t>(record_state::in_sync));

	chain_block_id id;
	auto res = q.execute();
	if(res) {
		auto hash = res.value<octet_vector>(0);
		auto seq = res.value<std::uint64_t>(1);
		id = chain_block_id{seq.value_or(0), hash.value_or(octet_vector{})};
	}
	return id;
}

record_handle record_storage::find_last() const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state, data_ref FROM record WHERE"
		" seq = (SELECT max(seq) FROM record WHERE state = :state);");
	q.bind(":state", static_cast<std::int64_t>(record_state::in_sync));
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_root() const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state, data_ref FROM record WHERE seq = :seq AND state = :state;");
	q.bind(":seq", static_cast<std::uint64_t>(1));
	q.bind(":state", static_cast<std::int64_t>(record_state::in_sync));
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_last(object_id const& oid) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state, data_ref FROM record WHERE"
		" seq = (SELECT max(seq) FROM record WHERE state = :state AND oid = :o);");
	q.bind(":state", static_cast<std::int64_t>(record_state::in_sync));
	q.bind(":o", oid.value());
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_first(object_id const& oid) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state, data_ref FROM record WHERE"
		" seq = (SELECT min(seq) FROM record WHERE state = :state AND oid = :o);");
	q.bind(":state", static_cast<std::int64_t>(record_state::in_sync));
	q.bind(":o", oid.value());
	return impl_->load_record(q.execute());
}

record_handle record_storage::find(octet_vector const& hash) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state, data_ref FROM record"
		" WHERE hash = :h;");
	q.bind(":h", hash);
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_tag(octet_vector const& tag) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, seq, hash, parent_hash, state, data_ref FROM record"
		" WHERE tag = :t;");
	q.bind(":t", tag);
	return impl_->load_record(q.execute());
}

//Problem:
// data change might have multiple object changes, how to handle the prev_object_tag here?
// The prev object tag is ignored for now, see later on if it is needed and if it should be in the record itself

record_handle record_storage::create(chain_block const& rec, record_state state, record_data_handle data_handle)
{
	LOG_TRACE("creating record to storage %", to_hex(rec.tag()));
	auto q = impl_->db->prepare(
		"INSERT INTO record(tag, seq, hash, parent_hash, oid, state, data_ref, record)"
		" VALUES(:tag, :seq, :hash, :parent_hash, :oid, :state, :data_ref, :record);");

	q.bind(":tag", rec.tag());
	if(rec.sequence() && !rec.parent_hash().empty()) {
		q.bind(":seq", rec.sequence().value);
		q.bind(":hash", rec.hash());
		q.bind(":parent_hash", rec.parent_hash());
	} else {
		q.bind(":seq");
		q.bind(":hash");
		q.bind(":parent_hash");
	}
	q.bind(":oid", octet_vector{});
	q.bind(":state", static_cast<std::int64_t>(state));
	q.bind(":data_ref", data_handle ? data_handle->local_id() : 0);
	q.bind(":record", serialisation::asn_der_serialise(rec));
	q.execute();

	return find_tag(rec.tag());
}

}
