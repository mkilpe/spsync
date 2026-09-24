#include "data_store.hpp"

#include <spsync/protocol/data_protocol.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <chrono>
#include <algorithm>
#include <set>
#include <vector>

namespace securepath::sync {
/*
	database table 'data_activity': the uploads that have not completed
		data_id: the data as blob (primary key)
		touched: seconds since epoch of the last manifest or chunk
*/

server_data_store::server_data_store(database::connection_ptr db, std::filesystem::path data_root, data_quota quota, transfer_quota transfer)
: db_(db)
, store_(db, std::move(data_root))
, table_(db)
, quota_(quota)
, budget_(transfer)
{
	if(!db_->has_table("data_activity")) {
		db_->prepare("CREATE TABLE data_activity("
			"data_id BLOB PRIMARY KEY,"
			"touched INTEGER);").execute();
	}
	// the counters start from the tables, once
	used_bytes_ = table_.total_enc_size();
	auto activity = db_->prepare("SELECT count(*) FROM data_activity;");
	uploads_in_progress_ = static_cast<std::uint64_t>(activity.execute().value<std::int64_t>(0).value_or(0));
}

util::result<have_bitmap> server_data_store::open(data_descriptor const& descriptor, data_manifest const* manifest, time_point now) {
	std::unique_lock lock{mutex_};
	util::result<have_bitmap> ret;
	bool const known = store_.find(descriptor.manifest_digest).has_value();
	if(quota_.max_data_size != 0 && descriptor.enc_size > quota_.max_data_size) {
		ret = make_error(protocol::errc::data_too_big);
	} else if(!known && quota_.max_storage_bytes != 0
		&& used_bytes_ + descriptor.enc_size > quota_.max_storage_bytes) {
		// a known data holds its reservation already: a resume is never refused
		ret = make_error(protocol::errc::data_quota_exceeded);
	} else {
		auto row = manifest ? store_.register_data(descriptor, *manifest) : store_.register_data(descriptor);
		if(row) {
			if(!known) {
				used_bytes_ += descriptor.enc_size;
			}
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

util::result<have_bitmap> server_data_store::open_upload(data_descriptor const& descriptor, data_manifest const& manifest, time_point now) {
	return open(descriptor, &manifest, now);
}

util::result<have_bitmap> server_data_store::open_replica(data_descriptor const& descriptor, time_point now) {
	return open(descriptor, nullptr, now);
}

bool server_data_store::replica_pulled(data_id const& id, time_point now) {
	return chunk_kept(id, now);
}

util::result<incoming_chunk> server_data_store::begin_chunk(data_id const& id, std::uint64_t chunk_no, time_point now) {
	// an incoming chunk moves but is not assigned: every outcome is returned where it is known
	if(!store_.has_manifest(id)) {
		return make_error(protocol::errc::no_such_upload);
	}
	auto const row = store_.find(id);
	if(row && row->have.test(chunk_no)) {
		// held already: nothing to stage for it, whatever a stale sender thinks
		return make_error(protocol::errc::invalid_data_chunk);
	}
	auto incoming = store_.begin_chunk(id, chunk_no);
	if(!incoming) {
		return make_error(protocol::errc::invalid_data_chunk);
	}
	std::unique_lock lock{mutex_};
	touch(id, now);
	return std::move(*incoming);
}

util::result<bool> server_data_store::finish_chunk(data_id const& id, incoming_chunk& incoming, time_point now) {
	util::result<bool> ret;
	auto const chunk_no = incoming.chunk_no();
	if(incoming.finish()) {
		ret = chunk_kept(id, now);
	} else {
		LOG_INFO("refused a chunk that is not the manifest's [data_id={}, chunk={}]", to_hex(id), chunk_no);
		ret = make_error(protocol::errc::invalid_data_chunk);
	}
	return ret;
}

/// a chunk was kept: the upload goes on, or the data is complete now (true)
bool server_data_store::chunk_kept(data_id const& id, time_point now) {
	auto const row = store_.find(id);
	bool const complete = row && row->state == record_data_state::in_sync;
	std::unique_lock lock{mutex_};
	if(complete) {
		forget_activity(id);
	} else {
		touch(id, now);
	}
	return complete;
}

util::result<served_data> server_data_store::open_download(data_descriptor const& descriptor) const {
	util::result<served_data> ret{make_error(protocol::errc::data_not_held)};
	auto const row = store_.find(descriptor.manifest_digest);
	auto manifest = store_.manifest(descriptor.manifest_digest);
	if(row && manifest && row->descriptor == descriptor) {
		ret = served_data{std::move(*manifest), row->have};
	}
	return ret;
}

util::result<octet_vector> server_data_store::serve_piece(data_id const& id, std::uint64_t chunk_no, std::uint64_t offset, std::uint32_t size, time_point now
	, bool charged) {
	util::result<octet_vector> ret{make_error(protocol::errc::data_not_held)};
	auto const row = store_.find(id);
	// offset and size are the asker's: checked without adding them up
	bool const held = row && row->have.test(chunk_no) && size != 0 && size <= protocol::max_data_piece_size
		&& row->descriptor.chunk_holds_range(chunk_no, offset, size);
	if(held && charged && !budget_.charge(size, now)) {
		ret = make_error(protocol::errc::data_transfer_quota_exceeded);
	} else if(held) {
		auto piece = store_.read_chunk_piece(id, chunk_no, offset, size);
		if(piece) {
			ret = std::move(*piece);
		}
	}
	return ret;
}

std::optional<data_state_row> server_data_store::find(data_id const& id) const {
	return store_.find(id);
}

std::uint64_t server_data_store::used_bytes() const {
	return used_bytes_;
}

std::vector<data_state_row> server_data_store::complete_data() const {
	std::vector<data_state_row> ret;
	for(auto const local_id : table_.all_ids()) {
		auto row = table_.find(local_id);
		if(row && row->state == record_data_state::in_sync) {
			ret.push_back(std::move(*row));
		}
	}
	return ret;
}

std::uint64_t server_data_store::uploads_in_progress() const {
	return uploads_in_progress_;
}

std::size_t server_data_store::drop(std::vector<data_id> const& ids) {
	std::uint64_t freed = 0;
	for(auto const& id : ids) {
		if(auto const row = store_.find(id)) {
			freed += row->descriptor.enc_size;
		}
	}
	auto const removed = store_.remove(ids);
	used_bytes_ -= std::min<std::uint64_t>(freed, used_bytes_);
	return removed;
}

std::size_t server_data_store::release(std::vector<data_id> const& ids) {
	std::unique_lock lock{mutex_};
	for(auto const& id : ids) {
		forget_activity(id);
	}
	return drop(ids);
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

	std::vector<data_id> expired;
	for(auto const& id : untouched) {
		auto const row = store_.find(id);
		if(row && row->state != record_data_state::in_sync) {
			LOG_INFO("incomplete upload expired [data_id={}, held {}/{} chunks]", to_hex(id), row->have.count(), row->have.size());
			expired.push_back(id);
		}
		forget_activity(id);
	}
	return drop(expired);
}

bool server_data_store::has_activity(data_id const& id) const {
	auto q = db_->prepare("SELECT count(*) FROM data_activity WHERE data_id = :id;");
	q.bind(":id", id);
	auto res = q.execute();
	return res.value<std::int64_t>(0).value_or(0) != 0;
}

void server_data_store::touch(data_id const& id, time_point now) {
	if(!has_activity(id)) {
		++uploads_in_progress_;
	}
	auto q = db_->prepare(
		"INSERT INTO data_activity(data_id, touched) VALUES(:id, :t)"
		" ON CONFLICT(data_id) DO UPDATE SET touched = excluded.touched;");
	q.bind(":id", id);
	q.bind(":t", seconds_since_epoch(now));
	q.execute();
}

void server_data_store::forget_activity(data_id const& id) {
	if(has_activity(id)) {
		--uploads_in_progress_;
		auto q = db_->prepare("DELETE FROM data_activity WHERE data_id = :id;");
		q.bind(":id", id);
		q.execute();
	}
}

}
