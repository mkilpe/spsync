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
		, record_tag prev_tag, sequence_number seq, record_state state, std::uint64_t data_ref)
	: db_(db)
	, record_key_(record_key)
	, tag_(std::move(tag))
	, prev_tag_(std::move(prev_tag))
	, seq_(seq)
	, state_(state)
	, data_ref_(data_ref)
	{}

	virtual sequence_number seq() const {
		std::unique_lock lock{mutex_};
		return seq_;
	}

	virtual record_tag tag() const {
		std::unique_lock lock{mutex_};
		return tag_;
	}

	virtual record_tag previous_tag() const {
		std::unique_lock lock{mutex_};
		return prev_tag_;
	}

	virtual record_state state() const {
		std::unique_lock lock{mutex_};
		return state_;
	}

	virtual void set_state(record_state state, sequence_number server_seq) {
		std::unique_lock lock{mutex_};
		state_ = state;
		seq_ = server_seq;

		//update state in database
		auto q = db_->prepare("UPDATE record SET state = :state, seq = :seq WHERE key = :k;");
		q.bind(":state", static_cast<std::uint64_t>(state_));
		q.bind(":seq", server_seq.value);
		q.bind(":k", record_key_);
		q.execute();
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

	//q: cache serialised record too ?
	virtual serialised_record record() const {
		auto q = db_->prepare("SELECT record FROM record WHERE key = :k;");
		q.bind(":k", record_key_);
		auto res = q.execute();

		if(!res) {
			throw make_error(securepath::errc::invalid_data, "failed to query serialised record from database");
		}

		return database::extract_column_type<serialised_record>(res, 0);
	}

private:
	mutable std::mutex mutex_;
	database::connection_ptr db_;

	// -- cached data --
	std::uint64_t record_key_;
	record_tag tag_;
	record_tag prev_tag_;
	sequence_number seq_;
	record_state state_;
	std::uint64_t data_ref_;
};

}

/*
	database table 'record':
		key: arbitrary table index as integer (primary key)
		tag: record tag as blob
		prev_tag: previous record tag as blob
		prev_object_tag: previous record tag for the same object as blob
		seq: server sequence as integer
		oid: object id as blob
		state: record state as integer
		data_ref: unique id to record data database table as integer
		record: serialised record as blob
*/

struct record_storage::impl {
	impl(database::connection_ptr conn)
	: db(conn)
	{
		if(!db->has_table("record")) {
			db->prepare("CREATE TABLE record("
				"key INTEGER PRIMARY KEY,"
				"tag BLOB UNIQUE,"
				"prev_tag BLOB,"
				"prev_object_tag BLOB,"
				"seq INTEGER UNIQUE,"
				"oid BLOB,"
				"state INTEGER,"
				"data_ref INTEGER,"
				"record BLOB);").execute();
		}
	}

	// construct record handle from query (SELECT key, tag, prev_tag, seq, state, data_ref ... )
	record_handle construct_record(std::uint64_t key, database::query const& q) {
		auto tag = q.value<octet_vector>(1);
		auto prev_tag = q.value<octet_vector>(2);
		auto seq = q.value<std::uint64_t>(3);
		auto state = q.value<std::uint64_t>(4);
		auto data_ref = q.value<std::uint64_t>(5);

		//check if the data is valid, notice that data_ref might not be set
		if(!tag || !seq || !state) {
			LOG_WARN("invalid record storage entry [key=%1%]", key);
			throw make_error(securepath::errc::invalid_data, "failed to interpret record columns");
		}

		return std::make_shared<database_record>
			( db
			, key
			, std::move(*tag)
			, prev_tag ? std::move(*prev_tag) : octet_vector{}
			, sequence_number{*seq}
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

sequence_number record_storage::last_sequence_number() const {
	auto q = impl_->db->prepare("SELECT max(seq) FROM record;");
	auto res = q.execute();
	if(!res) {
		throw make_error(securepath::errc::no_such_data);
	}
	auto data = res.value<std::uint64_t>(0);
	return sequence_number{data.value_or(0)};
}

record_handle record_storage::find_last() const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, prev_tag, seq, state, data_ref FROM record"
		" WHERE seq = (SELECT max(seq) FROM record);");
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_last(object_id const& oid) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, prev_tag, seq, state, data_ref FROM record"
		" WHERE seq = (SELECT max(seq) FROM record WHERE oid = :o);");
	q.bind(":o", oid.value());
	return impl_->load_record(q.execute());
}

record_handle record_storage::find_first(object_id const& oid) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, prev_tag, seq, state, data_ref FROM record"
		" WHERE seq = (SELECT min(seq) FROM record WHERE oid = :o);");
	q.bind(":o", oid.value());
	return impl_->load_record(q.execute());
}

record_handle record_storage::find(record_tag const& tag) const {
	auto q = impl_->db->prepare(
		"SELECT key, tag, prev_tag, seq, state, data_ref FROM record"
		" WHERE tag = :t;");
	q.bind(":t", tag);
	return impl_->load_record(q.execute());
}


//Problem:
// data change might have multiple object changes, how to handle the prev_object_tag here?
// The prev object tag is ignored for now, see later on if it is needed and if it should be in the record itself

record_handle record_storage::create(serialised_record const& rec, record_tag const& previous_tag,
									 record_state state, record_data_handle data_handle)
{
	LOG_TRACE("creating record to storage %", to_hex(rec.tag()));
	auto q = impl_->db->prepare(
		"INSERT INTO record(tag, prev_tag, prev_object_tag, seq, oid, state, data_ref, record)"
		" VALUES(:tag, :prev_tag, :prev_object_tag, :seq, :oid, :state, :data_ref, :record);");
	q.bind(":tag", rec.tag());
	q.bind(":prev_tag", previous_tag);
	q.bind(":prev_object_tag", octet_vector{});
	q.bind(":seq", rec.server_sequence().value);
	q.bind(":oid", octet_vector{});
	q.bind(":state", static_cast<std::uint64_t>(state));
	q.bind(":data_ref", data_handle ? data_handle->local_id() : 0);
	q.bind(":record", serialisation::asn_der_serialise(rec));
	q.execute();

	return find(rec.tag());
}

}
