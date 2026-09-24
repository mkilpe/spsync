#include "data_sync.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <algorithm>

#define LINFO(format, ...) LOG_INFO(format " (rsid={})" __VA_OPT__(,) __VA_ARGS__, config_.log_id)
#define LWARN(format, ...) LOG_WARN(format " (rsid={})" __VA_OPT__(,) __VA_ARGS__, config_.log_id)

namespace securepath::sync {
namespace {

bool is_error(std::optional<error> const& err, protocol::errc code) {
	return err && err->code() == make_error_code(code);
}

/// a data that is on its way, in either direction
bool in_transfer(record_data_state state) {
	return state == record_data_state::upload_pending || state == record_data_state::download_pending
		|| state == record_data_state::remote_not_complete;
}

}

data_sync::data_sync(comm_input& comm, crypto_context& crypto, record_storage& records, record_data_store& store
	, sync_engine_config const& config, events ev)
: comm_(comm)
, crypto_(crypto)
, records_(records)
, store_(store)
, config_(config)
, events_(std::move(ev))
{}

void data_sync::on_connected() {
	uploads_.clear();
	failed_uploads_.clear();
	downloads_.clear();
	failed_downloads_.clear();
}

void data_sync::on_disconnected() {
	uploads_.clear();
	downloads_.clear();
}

void data_sync::request_transfers() {
	request_uploads();
	mark_auto_fetch();
	request_downloads();
}

/**
 * Ask comm for the transfers a state is owed: every data of a server confirmed record
 * in that state that is not on its way already and was not refused during this
 * connection, in the order of the records.
 */
template<typename Ask>
void data_sync::request_transfers_of(record_data_state state, std::map<request_handle, data_id>& on_their_way
	, std::set<data_id> const& refused, char const* what, Ask ask) {
	for(auto const& id : records_.confirmed_data_in_state(state)) {
		bool const asked = std::any_of(on_their_way.begin(), on_their_way.end(), [&](auto const& t) { return t.second == id; });
		if(!asked && !refused.contains(id)) {
			auto const handle = ask(id);
			on_their_way[handle] = id;
			LINFO("requested record data {} [data_id = {}, request handle = {}]", what, to_hex(id), handle);
		}
	}
}

/**
 * Ask comm for the uploads that are owed: the upload_pending data of server
 * confirmed records in commit order (RD4: an upload starts after the record is
 * acked; after a reconnect this is the resume). A data already asked for, or refused
 * during this connection, is left alone.
 */
void data_sync::request_uploads() {
	request_transfers_of(record_data_state::upload_pending, uploads_, failed_uploads_, "upload"
		, [this](data_id const& id) { return comm_.upload_data(id); });
}

/**
 * Ask comm for the downloads that are wanted: the download_pending data of server
 * confirmed records. A data already asked for, or whose fetch failed during this
 * connection, is left alone (a failed one until it is asked for again).
 */
void data_sync::request_downloads() {
	request_transfers_of(record_data_state::download_pending, downloads_, failed_downloads_, "download"
		, [this](data_id const& id) { return comm_.fetch_data(id); });
}

/// RD6 fetch policy: small enough data of others is wanted as soon as its record is here
void data_sync::mark_auto_fetch() {
	if(config_.auto_fetch_max_size != 0) {
		for(auto const& id : records_.confirmed_data_in_state(record_data_state::deferred)) {
			auto const row = store_.find(id);
			// what the server refused during this connection stays as it is
			if(row && row->descriptor.enc_size <= config_.auto_fetch_max_size && !failed_downloads_.contains(id)) {
				set_state(id, record_data_state::download_pending);
			}
		}
	}
}

void data_sync::set_state(data_id const& id, record_data_state state) {
	store_.set_state(id, state);
	events_.state_changed(id, state);
}

void data_sync::on_upload_answer(request_handle handle, std::optional<error> const& err) {
	auto it = uploads_.find(handle);
	if(it != uploads_.end()) {
		data_id const id = it->second;
		uploads_.erase(it);
		if(is_error(err, protocol::errc::data_pruned)) {
			on_data_pruned(id, *err);
		} else if(err) {
			LWARN("record data upload failed [data_id = {}]: {}", to_hex(id), *err);
			failed_uploads_.insert(id);
			events_.transfer_failed(id, *err);
		} else {
			mark_uploaded(id);
		}
	}
}

void data_sync::mark_uploaded(data_id const& id) {
	auto const row = store_.find(id);
	if(row && row->state == record_data_state::upload_pending) {
		LINFO("record data uploaded [data_id = {}]", to_hex(id));
		set_state(id, record_data_state::in_sync);
	}
}

/**
 * The server let the data go under the retention policy of the storage (RD9): a
 * superseded version, its record stays. Nobody gets it from the server any more, so
 * chunks held only to be uploaded go as well; the application is told why.
 */
void data_sync::on_data_pruned(data_id const& id, error const& err) {
	LINFO("record data was pruned by the retention policy of the storage [data_id = {}]", to_hex(id));
	auto const row = store_.find(id);
	if(row && row->state != record_data_state::in_sync) {
		store_.prune(id);
		events_.state_changed(id, record_data_state::pruned);
	}
	events_.transfer_failed(id, err);
}

void data_sync::on_download_answer(request_handle handle, std::optional<error> const& err) {
	auto it = downloads_.find(handle);
	if(it != downloads_.end()) {
		data_id const id = it->second;
		downloads_.erase(it);
		auto const row = store_.find(id);
		if(!err && row && row->state == record_data_state::in_sync) {
			// the store flipped the state with the last chunk
			LINFO("record data downloaded [data_id = {}]", to_hex(id));
			events_.state_changed(id, record_data_state::in_sync);
		} else if(is_error(err, protocol::errc::data_pruned)) {
			on_data_pruned(id, *err);
		} else if(is_error(err, protocol::errc::data_not_held)) {
			// the upload is still in progress over there: notify_data brings us back
			LINFO("record data not complete at the holders yet [data_id = {}]", to_hex(id));
			set_state(id, record_data_state::remote_not_complete);
		} else {
			on_download_failed(id, err);
		}
	}
}

void data_sync::on_download_failed(data_id const& id, std::optional<error> const& err) {
	if(is_error(err, protocol::errc::unknown_data)) {
		// no record on the server names the data any more: a history cut took it
		// (RD9). We may still hold the record, but the data is gone over there - not
		// wanted again by itself, only when somebody asks. Deferred is what auto
		// fetch picks up, so the refusal is remembered for this connection - the
		// next one is another chance, the record may only have been late over there
		LINFO("record data is not known to the server any more [data_id = {}]", to_hex(id));
		set_state(id, record_data_state::deferred);
		failed_downloads_.insert(id);
		events_.transfer_failed(id, *err);
	} else {
		auto const failure = err.value_or(make_error(securepath::errc::invalid_state, "download ended incomplete"));
		LWARN("record data download failed [data_id = {}]: {}", to_hex(id), failure);
		failed_downloads_.insert(id);
		events_.transfer_failed(id, failure);
	}
}

void data_sync::on_data_announced(data_id const& id) {
	auto const row = store_.find(id);
	if(row && row->state == record_data_state::remote_not_complete) {
		set_state(id, record_data_state::download_pending);
	}
	failed_downloads_.erase(id);
	request_downloads();
}

/// ask for a data that is not held: true when it is wanted now (or was already)
bool data_sync::want_data(data_id const& id) {
	auto const row = store_.find(id);
	// pruned: the server may not have cut yet, or not as far - asking tells
	bool const fetchable = row && (row->state == record_data_state::deferred
		|| row->state == record_data_state::removed || row->state == record_data_state::remote_not_complete
		|| row->state == record_data_state::pruned);
	if(fetchable) {
		set_state(id, record_data_state::download_pending);
	}
	failed_downloads_.erase(id);
	return fetchable || (row && row->state == record_data_state::download_pending);
}

data_writer data_sync::stream(encryption_key const& key, std::uint32_t chunk_size, record_data& source) {
	auto writer = store_.create(key, chunk_size);
	copy_record_data(source, writer);
	return writer;
}

void data_sync::prune_superseded(sequence_number anchor, std::uint32_t kept_versions) {
	std::size_t pruned = 0;
	for(auto const& id : records_.superseded_data_below(anchor, kept_versions)) {
		auto const row = store_.find(id);
		if(row && !in_transfer(row->state) && store_.prune(id)) {
			++pruned;
			events_.state_changed(id, record_data_state::pruned);
		}
	}
	if(pruned != 0) {
		LINFO("pruned {} record data of superseded versions [kept versions={}]", pruned, kept_versions);
	}
}

void data_sync::sweep() {
	auto const removed = store_.remove(records_.unreferenced_data());
	if(removed != 0) {
		LINFO("dropped {} unreferenced record data", removed);
	}
}

record_data_handle data_sync::open_change_data(change const& c) const {
	record_data_handle ret;
	auto const info = c.header.data_info();
	if(c.data.data && info) {
		// the data key derives from the group key of the header's sequence, which
		// may differ from the record's after a rebase; colliding rotations (D9)
		// leave several candidates
		auto const keys = crypto_.enc_keys().find_all(info->key_seq);
		if(!keys.empty()) {
			ret = store_.open(keys, *c.data.data, *info);
		}
	}
	return ret;
}

std::optional<data_sync::adoption> data_sync::plan_adoption(read_change_result const& read) const {
	std::optional<adoption> ret;
	auto const info = read ? read->header.data_info() : std::nullopt;
	if(info && read->data.data) {
		auto const& wanted = *read->data.data;
		auto const row = store_.find(wanted.manifest_digest);
		bool const held = row && row->have.complete();
		auto const content = held ? std::nullopt : store_.find_content(info->content_digest, wanted.manifest_digest);
		auto const source_keys = content ? crypto_.enc_keys().find_all(content->header.key_seq) : std::vector<encryption_key>{};
		if(!source_keys.empty()) {
			ret = adoption{store_.open(source_keys, content->descriptor, content->header)
				, crypto_.enc_keys().find_all(info->key_seq), wanted, *info};
		}
	}
	return ret;
}

bool data_sync::adopt(adoption const& plan) const {
	bool adopted = false;
	try {
		for(auto const& key : plan.keys) {
			adopted = adopted || (plan.source && store_.adopt_content(*plan.source, key, plan.wanted, plan.header));
		}
	} catch(std::exception const& e) {
		LWARN("could not rebuild record data from held content: {}", e.what());
	}
	return adopted;
}

record_data_handle data_sync::fetch_change_data(read_change_result const& read) {
	record_data_handle ret;
	if(read) {
		ret = open_change_data(*read);
	}
	if(ret && want_data(read->data.data->manifest_digest)) {
		request_downloads();
	}
	return ret;
}

}
