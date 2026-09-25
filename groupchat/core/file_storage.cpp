#include "file_storage.hpp"

#include <securepath/log/log.hpp>
#include <securepath/serialisation/sequence.hpp>
#include <spsync/client/record_util.hpp>

namespace securepath::groupchat {

/*
	tables sync_file / sync_pending_file: an object_store (see there)
	table 'sync_file_data': data_id BLOB PRIMARY KEY, id BLOB - the file a data id names,
	for the data state events
*/

file_storage::file_storage(database::connection_ptr db)
: store_(db, "sync_file", "sync_pending_file")
, db_(std::move(db))
{
	if(!db_->has_table("sync_file_data")) {
		db_->prepare("CREATE TABLE sync_file_data("
			"data_id BLOB PRIMARY KEY,"
			"id BLOB);").execute();
	}
}

file_change file_storage::insert(file_id const& id, stored_file const& file, bool pending) {
	database::transaction t{*db_};
	auto const change = store_.insert(id, serialisation::asn_der_serialise(file), file.data.shared_time
		, file.seq, file.iid, pending);
	auto q = db_->prepare("INSERT OR REPLACE INTO sync_file_data(data_id, id) VALUES(:d, :id);");
	q.bind(":d", file.data_id);
	q.bind(":id", id.value());
	q.execute();
	return file_change{change.new_index, change.old_index, id, pending};
}

namespace {

file_storage::row row_of(stored_object const& o) {
	return file_storage::row{o.id, serialisation::asn_der_deserialise<stored_file>(o.payload), o.index, o.pending};
}

}

std::deque<file_storage::row> file_storage::get(file_search s) const {
	std::deque<row> ret;
	for(auto const& o : store_.get(s)) {
		ret.push_back(row_of(o));
	}
	return ret;
}

std::optional<file_storage::row> file_storage::find(file_id const& id) const {
	std::optional<row> ret;
	if(auto o = store_.find(id)) {
		ret = row_of(*o);
	}
	return ret;
}

std::optional<file_id> file_storage::find_by_data(octet_vector const& data_id) const {
	std::optional<file_id> ret;
	auto q = db_->prepare("SELECT id FROM sync_file_data WHERE data_id = :d;");
	q.bind(":d", data_id);
	if(auto res = q.execute()) {
		ret = file_id{res.value<octet_vector>(0).value()};
	}
	return ret;
}

sync::sequence_number file_storage::latest_sequence() const {
	return store_.latest_sequence();
}

bool file_storage::remove_pending(file_id const& id) {
	return store_.remove_pending(id);
}

std::optional<stored_file> file_of(sync::single_data_change const& c) {
	std::optional<stored_file> ret;
	auto entry = c.header.metadata().find<file_data>(groupchat_file_id);
	if(entry && c.data.data) {
		ret = stored_file{*entry, user_id{c.signer.value_or(crypto::public_key_id{})}, c.internal_id, c.seq
			, c.data.data->manifest_digest, clock_type::now()};
	} else if(entry) {
		LOG_WARN("a file record without data [name={}]", entry->name);
	}
	return ret;
}

namespace {

void handle_files(file_storage& files, std::deque<sync::single_data_change> const& changes, bool pending) {
	for(auto const& c : changes) {
		if(c.data.previous_oid_record_tag.empty()) {
			if(auto file = file_of(c)) {
				files.insert(c.data.id, *file, pending);
			}
		}
	}
}

}

void sync_file_storage(file_storage& files, sync::record_storage const& records, sync::encryption_key_storage const& keys) {
	walk_data_changes(records, keys, files.latest_sequence(), [&](auto const& changes, bool pending) {
		handle_files(files, changes, pending);
	});
}

}
