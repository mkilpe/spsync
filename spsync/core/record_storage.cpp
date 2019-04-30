#include "record_storage.hpp"

#include <memory>
#include <mutex>

namespace securepath::sync {
namespace {

class database_record : public record_interface {
public:
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

	virtual void set_state(record_state state) {
		std::unique_lock lock{mutex_};
		state_ = state;
		//todo: update db
	}

	virtual record_data_handle data() {
		//todo: use data_ref_ to load from db
		return nullptr;
	}

	virtual const_record_data_handle data() const {
		//todo: use data_ref_ to load from db
		return nullptr;
	}

	virtual serialised_record record() const {
		return {};
	}

private:
	mutable std::mutex mutex_;
	database::connection_ptr db_;

	// -- cached data --
	std::uint64_t record_key_;
	sequence_number seq_;
	record_tag tag_;
	record_tag prev_tag_;
	record_state state_;
	std::uint64_t data_ref_{};
};

}

/*
	database table 'record':
		key: arbitrary table index as integer (primary key)
		tag: record tag as string
		prev_tag: previous record tag as string
		prev_object_tag: previous record tag for the same object as string
		seq: server sequence as integer
		oid: object id as string
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
				"tag STRING,"
				"prev_tag STRING,"
				"prev_object_tag STRING,"
				"seq INTEGER,"
				"oid STRING,"
				"state INTEGER,"
				"data_ref INTEGER,"
				"record BLOB);").execute();
		}
	}

	mutable std::mutex mutex_;
	database::connection_ptr db;

	//map record database key to the potential record handle
	std::unordered_map<std::uint64_t, std::weak_ptr<record_interface>> record_handles_;
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
	auto data = res.value<std::uint64_t>(1);
	if(!data) {
		throw make_error(securepath::errc::invalid_data, "failed to interpret record sequence number column");
	}
	return sequence_number{*data};
}

record_handle record_storage::find_last() const {
	return nullptr;
}

record_handle record_storage::find_last(object_id const& oid) const {
	return nullptr;
}

record_handle record_storage::find_first(object_id const& oid) const {
	return nullptr;
}

record_handle record_storage::find(record_tag const& tag) const {
	auto q = impl_->db->prepare("SELECT key, tag, prev_tag, seq, state, data_ref FROM record WHERE tag = :t;");
	q.bind(":t", tag);
	auto res = q.execute();

	record_handle record;
	if(res) {
		//todo: check cache, construct database_record if need be and add to the cache
	}
	return record;
}

record_handle record_storage::create(serialised_record const& rec, record_data_handle) {
	return nullptr;
}

}
