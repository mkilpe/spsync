#include "sync_engine.hpp"
#include "record_creator.hpp"
#include "types.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/protocol/types.hpp>

#include <securepath/log/log.hpp>

#include <map>
#include <mutex>

namespace securepath::sync {

class sync_engine::impl {
public:
	impl(comm_input& comm, encryption_key_storage& keys, sync_engine_config config)
	: comm(comm)
	, keys(keys)
	, records(comm.records())
	, config(std::move(config))
	, last_seen_sequence(records.last_sequence_number())
	{}

	void commit_record(record_handle h) {
		h->set_state(record_state::pending_commit);
		request_handle req = comm.commit_record(h);
		commit_requests[req] = h;
	}

	void update_record_commit_state(record_handle h, serialised_record const& record) {
		//record.deserialise_record([]{});
	}

	mutable engine_mutex_type mutex;
	comm_input& comm;
	encryption_key_storage& keys;
	record_storage& records;
	sync_engine_config config;
	engine_output* output{};

	sequence_number last_seen_sequence;
	std::map<request_handle, record_handle> commit_requests;
};

sync_engine::sync_engine(comm_input& comm, encryption_key_storage& keys, sync_engine_config config)
: impl_(std::make_unique<impl>(comm, keys, std::move(config)))
{
}

sync_engine::~sync_engine()
{
}

void sync_engine::set_output(engine_output* output) {
	std::unique_lock lock{impl_->mutex};
	impl_->output = output;
}

void sync_engine::set_config(sync_engine_config config) {
	std::unique_lock lock{impl_->mutex};
	impl_->config = std::move(config);
}


//--- comm_output interface, see comm/interface.hpp

void sync_engine::on_record_response(request_handle handle, result<std::deque<serialised_record>> const& res) {
	std::unique_lock lock{impl_->mutex};

	if(res) {
		for(auto&& rec : res.value()) {

		}
	} else {
		LOG_INFO("fetching records failed: error='%' (%)", res.get_error(), impl_->config.log_id);
		//network error?
	}
}

void sync_engine::on_data_response(request_handle handle, result<record_data_handle> const&) {

}

void sync_engine::on_commit_response(request_handle handle, result<serialised_record> const& res) {
	std::unique_lock lock{impl_->mutex};

	auto it = impl_->commit_requests.find(handle);
	if(it != impl_->commit_requests.end()) {
		if(res) {
			impl_->update_record_commit_state(it->second, res.value());
			impl_->commit_requests.erase(it);
		} else {
			LOG_INFO("committing failed: error='%' (%)", res.get_error(), impl_->config.log_id);
			//todo: handle correctly
		}
	} else {
		LOG_WARN("invalid request handle from comm-layer (%)", impl_->config.log_id);
	}
}

void sync_engine::on_data_uploaded(request_handle handle, std::optional<error>) {

}

void sync_engine::on_record_received(serialised_record const&) {

}


//--- engine_input interface, see interface.hpp

//f: for now just implement plain record without data
record_handle sync_engine::sync_object_change(object_id oid, metadata mdata, record_data_handle) {
	std::unique_lock lock{impl_->mutex};
	LOG_TRACE("sync object change: oid='%' (%)", oid.to_hex(), impl_->config.log_id);

	auto last_oid_record = impl_->records.find_last(oid);
	auto last_record = impl_->records.find_last();

	if(!last_record) {
		throw error(errc::invalid_record_chain_state, "Can't find last record, data change cannot be first record");
	}

	record_tag last_oid_tag = last_oid_record ? last_oid_record->tag() : record_tag{};

	data_change_record_creator creator(impl_->keys.current_key(), last_record->tag(), impl_->last_seen_sequence);
	creator.add_change(std::move(oid), last_oid_tag, std::move(mdata));

	record_handle h = impl_->records.create(serialised_record(creator.result(), creator.authentication_tag()));
	//f: handle record data

	impl_->commit_record(h);

	return h;
}

record_handle sync_engine::sync_user_change(users user_change, metadata mdata) {
	std::unique_lock lock{impl_->mutex};
	LOG_TRACE("sync user change: users='%' (%)", user_change, impl_->config.log_id);

	auto last_record = impl_->records.find_last();

	user_change_record_creator creator(impl_->keys.current_key()
		, last_record ? last_record->tag() : record_tag{}, impl_->last_seen_sequence);

	creator.set_change(std::move(user_change), std::move(mdata));
	//todo: new encryption key here and such with the change

	record_handle h = impl_->records.create(serialised_record(creator.result(), creator.authentication_tag()));
	impl_->commit_record(h);

	return h;
}

record_handle sync_engine::sync_segment_end(metadata mdata) {
	std::unique_lock lock{impl_->mutex};
	LOG_TRACE("sync segment end (%)", impl_->config.log_id);

	auto last_record = impl_->records.find_last();

	if(!last_record) {
		throw error(errc::invalid_record_chain_state, "Can't find last record, segment cannot be first record");
	}

	segment_record_creator creator(impl_->keys.current_key(), last_record->tag(), impl_->last_seen_sequence);

	//needs the start, end sequences and the record tags
	//creator.add_change(std::move(mdata));

	record_handle h = impl_->records.create(serialised_record(creator.result(), creator.authentication_tag()));
	impl_->commit_record(h);

	return h;
}

}
