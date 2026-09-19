#include "data_store.hpp"

#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <chrono>
#include <set>
#include <vector>

namespace securepath::sync {
namespace {

std::int64_t seconds_since_epoch(time_point t) {
	return std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
}

}

/*
	database table 'data_activity': the uploads that have not completed
		data_id: the data as blob (primary key)
		touched: seconds since epoch of the last manifest or chunk
*/

server_data_store::server_data_store(database::connection_ptr db, std::filesystem::path data_root, data_quota quota)
: db_(db)
, store_(db, std::move(data_root))
, table_(db)
, quota_(quota)
{
	if(!db_->has_table("data_activity")) {
		db_->prepare("CREATE TABLE data_activity("
			"data_id BLOB PRIMARY KEY,"
			"touched INTEGER);").execute();
	}
}

util::result<have_bitmap> server_data_store::open_upload(data_descriptor const& descriptor, data_manifest const& manifest, time_point now) {
	std::unique_lock lock{mutex_};
	util::result<have_bitmap> ret;
	bool const known = store_.find(descriptor.manifest_digest).has_value();
	if(quota_.max_data_size != 0 && descriptor.enc_size > quota_.max_data_size) {
		ret = make_error(protocol::errc::data_too_big);
	} else if(!known && quota_.max_storage_bytes != 0
		&& table_.total_enc_size() + descriptor.enc_size > quota_.max_storage_bytes) {
		// a known data holds its reservation already: a resume is never refused
		ret = make_error(protocol::errc::data_quota_exceeded);
	} else {
		auto row = store_.register_data(descriptor, manifest);
		if(row) {
			if(row->state != record_data_state::in_sync) {
				touch(descriptor.manifest_digest, now);
			}
			ret = std::move(row->have);
		} else {
			ret = make_error(protocol::errc::invalid_data_manifest);
		}
	}
	return ret;
}

util::result<bool> server_data_store::store_chunk(data_id const& id, std::uint64_t chunk_no, octet_span encrypted, time_point now) {
	util::result<bool> ret;
	if(!store_.manifest(id)) {
		ret = make_error(protocol::errc::no_such_upload);
	} else if(!store_.store_chunk(id, chunk_no, encrypted)) {
		LOG_INFO("refused a chunk that is not the manifest's [data_id={}, chunk={}]", to_hex(id), chunk_no);
		ret = make_error(protocol::errc::invalid_data_chunk);
	} else {
		auto const row = store_.find(id);
		bool const complete = row && row->state == record_data_state::in_sync;
		std::unique_lock lock{mutex_};
		if(complete) {
			forget_activity(id);
		} else {
			touch(id, now);
		}
		ret = complete;
	}
	return ret;
}

std::optional<data_state_row> server_data_store::find(data_id const& id) const {
	return store_.find(id);
}

std::optional<octet_vector> server_data_store::read_chunk(data_id const& id, std::uint64_t chunk_no) const {
	return store_.read_chunk(id, chunk_no);
}

std::uint64_t server_data_store::used_bytes() const {
	return table_.total_enc_size();
}

std::size_t server_data_store::expire_incomplete(time_point untouched_since) {
	std::unique_lock lock{mutex_};
	auto q = db_->prepare("SELECT data_id FROM data_activity WHERE touched < :t;");
	q.bind(":t", seconds_since_epoch(untouched_since));

	// read first: the rows are deleted below
	std::vector<data_id> untouched;
	for(auto res = q.execute(); res; res.next()) {
		untouched.push_back(res.value<octet_vector>(0).value_or(octet_vector{}));
	}

	std::set<std::uint64_t> expired;
	for(auto const& id : untouched) {
		auto const row = store_.find(id);
		if(row && row->state != record_data_state::in_sync) {
			LOG_INFO("incomplete upload expired [data_id={}, held {}/{} chunks]", to_hex(id), row->have.count(), row->have.size());
			expired.insert(row->local_id);
		}
		forget_activity(id);
	}
	std::size_t removed = 0;
	if(!expired.empty()) {
		removed = store_.remove_unreferenced([&](std::uint64_t local_id) { return !expired.contains(local_id); });
	}
	return removed;
}

void server_data_store::touch(data_id const& id, time_point now) {
	auto q = db_->prepare(
		"INSERT INTO data_activity(data_id, touched) VALUES(:id, :t)"
		" ON CONFLICT(data_id) DO UPDATE SET touched = excluded.touched;");
	q.bind(":id", id);
	q.bind(":t", seconds_since_epoch(now));
	q.execute();
}

void server_data_store::forget_activity(data_id const& id) {
	auto q = db_->prepare("DELETE FROM data_activity WHERE data_id = :id;");
	q.bind(":id", id);
	q.execute();
}

}
