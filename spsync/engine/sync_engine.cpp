#include "sync_engine.hpp"
#include "record_creator.hpp"

#include <spsync/core/encryption_key_storage.hpp>

#include <mutex>

namespace securepath::sync {

class sync_engine::impl {
public:
	impl(comm_input& comm, encryption_key_storage& keys, sync_engine_config config)
	: comm(comm)
	, keys(keys)
	, records(comm.records())
	, config(std::move(config))
	{}

	mutable std::mutex mutex;
	comm_input& comm;
	encryption_key_storage& keys;
	record_storage& records;
	sync_engine_config config;
	engine_output* output{};
	sequence_number last_seen_sequence;
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


//--- engine_input interface, see interface.hpp

//f: for now just implement plain record without data
record_handle sync_engine::sync_object_change(object_id oid, metadata mdata, record_data_handle) {
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

	//todo: set record state .. h->set_state(record_authenticated | commit_pending);
	request_handle req = impl_->comm.commit_record(h);

	//todo: push pending commit to queue

	return h;
}

record_handle sync_engine::sync_user_change(users user_change, metadata mdata) {
	auto last_record = impl_->records.find_last();

	user_change_record_creator creator(impl_->keys.current_key()
		, last_record ? last_record->tag() : record_tag{}, impl_->last_seen_sequence);

	//needs new encryption key here
	//creator.add_change(std::move(user_change), std::move(mdata));

	record_handle h = impl_->records.create(serialised_record(creator.result(), creator.authentication_tag()));

	//todo: set record state .. h->set_state(record_authenticated | commit_pending);
	request_handle req = impl_->comm.commit_record(h);

	//todo: push pending commit to queue

	return h;
}

record_handle sync_engine::sync_segment_end(metadata mdata) {
	auto last_record = impl_->records.find_last();

	if(!last_record) {
		throw error(errc::invalid_record_chain_state, "Can't find last record, segment cannot be first record");
	}

	segment_record_creator creator(impl_->keys.current_key(), last_record->tag(), impl_->last_seen_sequence);

	//needs the start, end sequences and the record tags
	//creator.add_change(std::move(mdata));

	record_handle h = impl_->records.create(serialised_record(creator.result(), creator.authentication_tag()));

	//todo: set record state .. h->set_state(record_authenticated | commit_pending);
	request_handle req = impl_->comm.commit_record(h);

	//todo: push pending commit to queue

	return h;
}

}
