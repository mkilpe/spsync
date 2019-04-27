#include "record_storage.hpp"

namespace securepath::sync {

/*
	database table 'record_storage':
		key: arbitrary table index as integer (primary key)

*/

struct record_storage::impl {
	impl(database::connection_ptr conn)
	: db(conn)
	{
		if(!db->has_table("record_storage")) {
			db->prepare("CREATE TABLE record_storage(key INTEGER PRIMARY KEY, key BLOB);").execute();
		}
	}

	database::connection_ptr db;
};

record_storage::record_storage(database::connection_ptr conn)
: impl_(std::make_unique<impl>(conn))
{
}

record_storage::~record_storage()
{
}

sequence_number record_storage::last_sequence_number() const {
	return sequence_number{};
}

record_handle record_storage::find_last() const {
	return nullptr;
}

record_handle record_storage::find_last(object_id const&) const {
	return nullptr;
}

record_handle record_storage::find_first(object_id const&) const {
	return nullptr;
}

record_handle record_storage::find(record_tag const& tag) const {
	return nullptr;
}

record_handle record_storage::create(serialised_record const&) {
	return nullptr;
}

}
