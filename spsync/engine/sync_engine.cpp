#include "sync_engine.hpp"
#include "record_creator.hpp"
#include "record_verifier.hpp"
#include "types.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/protocol/types.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

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
	{}

	void commit_record(record_handle h) {
		h->set_state(record_state::pending_commit);
		request_handle req = comm.commit_record(h);
		LOG_INFO("trying to commit record to server [tag = %, request handle = %] (%)"
			, to_hex(h->tag()), req, config.log_id);
	}

	void update_record_commit_state(record_handle h, chain_block const& record, chain_block_id const& id) {
		if(record.check_matches_without_server_data(h->record())
			&& check_chain_block(record, id) == record_state::in_sync)
		{
			LOG_INFO("setting in sync state for record [block id = %, parent block = %, tag = %] (%)",
				id, to_hex(record.parent_hash()), to_hex(h->tag()), config.log_id);
			h->set_in_sync(id, record.parent_hash());
		} else {
			h->set_state(record_state::invalid);

			//t: handle error, what to do?
			LOG_WARN("Server returned invalid record [local tag=%, server tag=%] (%)"
				, to_hex(h->tag()), to_hex(record.tag()), config.log_id);
		}
	}

	void handle_decrypt_record(data_change_record_verifier const& ver) {

	}

	void handle_decrypt_record(user_change_record_verifier const& ver) {

	}

	void handle_decrypt_record(segment_record_verifier const& ver) {

	}

	record_state check_chain_block(chain_block const& record, chain_block_id const& id) {
		// needs to fulfil:
		//  parent.seq + 1 == record.sequence()
		//  parent.hash == record.parent_hash
		//  last_record.seq < record.sequence();

		record_state state = record_state::invalid;
		auto last_block = records.last_block();

		if(last_block.sequence < record.sequence()) {
			if(record.sequence() == sequence_number{1} && record.parent_hash().empty()) {
				// root record
				state = record_state::in_sync;
			} else {
				auto parent = records.find(record.parent_hash());
				if(parent) {
					if(parent->block_id().sequence+1 == record.sequence()) {
						// all good, we are in sync
						state = record_state::in_sync;
					} else {
						LOG_WARN("Record sequence does not match with its parent [block id = %, tag = %"
							", seq = %, parent seq = %, parent hash = %] (%)"
							, id, to_hex(record.tag()), to_hex(record.parent_hash()), record.sequence()
							, parent->block_id().sequence, config.log_id);
					}
				} else {
					LOG_TRACE("Record block with unknown parent [block id = %, tag = %, parent hash = %] (%)"
						, id, to_hex(record.tag()), to_hex(record.parent_hash()), config.log_id);

					if(last_block.sequence+1 < record.sequence()) {
						// if the sequence is bigger than the next one we are waiting, then try this block later on when we
						// have the missing blocks in between.
						state = record_state::pending_sync;
					}
				}
			}
		} else {
			LOG_WARN("Record block with sequence number that is already in use [block id = %, tag = %] (%)"
				, id, to_hex(record.tag()), config.log_id);
		}
		return state;
	}

	bool handle_block_chain(chain_block const& record, chain_block_id const& id) {
		auto state = check_chain_block(record, id);
		records.create(record, state);
		return state == record_state::in_sync;
	}

	template<typename Record>
	void handle_block(chain_block const& record, chain_block_id const& id, Record const& rec) {
		auto enc_key = keys.find(rec.encryption_key());
		if(enc_key) {
			record_verifier<Record> ver(*enc_key, rec, record.auth());
			if(ver.is_authentic()) {
				if(handle_block_chain(record, id)) {
					handle_decrypt_record(ver);
				}
			} else {
				LOG_WARN("Record is not authentic [block id = %, tag = %] (%)", id, to_hex(record.tag()), config.log_id);
			}
		} else {
			LOG_INFO("No valid key for record [block id = %, tag = %, key id = %] (%)", id, to_hex(record.tag()), rec.encryption_key(), config.log_id);
			// store for later, when we hopefully have the key
			records.create(record, record_state::pending_sync);
		}
	}

	void handle_incoming_record(chain_block const& record) {
		chain_block_id id{record.id()};
		LOG_INFO("received record block [block id = %, tag = %] (%)", id, to_hex(record.tag()), config.log_id);

		if(id.is_valid()) {
			auto handle = records.find(id.hash);
			if(!handle) {
				record.deserialise_record([&](auto const& rec) {
						this->handle_block(record, id, rec);
					});
			} else {
				LOG_TRACE("record block already known [block id = %, tag = %] (%)", id, to_hex(record.tag()), config.log_id);
			}
		} else {
			LOG_WARN("server sent invalid record block (%)", config.log_id);
		}
	}

public:
	mutable engine_mutex_type mutex;
	comm_input& comm;
	encryption_key_storage& keys;
	record_storage& records;
	sync_engine_config config;
	engine_output* output{};
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
void sync_engine::on_sequence_number_response(request_handle req_handle, result<sequence_number> const& res) {
	std::unique_lock lock{impl_->mutex};

}

void sync_engine::on_record_response(request_handle req_handle, result<std::deque<chain_block>> const& res) {
	std::unique_lock lock{impl_->mutex};
	LOG_INFO("on_record_received [request handle = %] (%)", req_handle, impl_->config.log_id);
	if(res) {
		for(auto&& block : res.value()) {
			impl_->handle_incoming_record(block);
		}
	} else {
		LOG_INFO("fetching records failed: error=% (%)", res.get_error(), impl_->config.log_id);
		//network error?
	}
}

void sync_engine::on_data_response(request_handle req_handle, result<record_data_handle> const&) {

}

void sync_engine::on_commit_response(request_handle req_handle, result<chain_block> const& res) {
	std::unique_lock lock{impl_->mutex};
	LOG_INFO("on_commit_response [request handle = %]", req_handle);

	if(res) {
		auto block = res.value();
		chain_block_id id = block.id();

		if(id.is_valid()) {
			auto handle = impl_->records.find_tag(block.tag());
			if(handle) {
				impl_->update_record_commit_state(handle, block, id);
			} else {
				LOG_WARN("commit reply with unknown tag [block id = %, tag = %] (%)", id, to_hex(block.tag()), impl_->config.log_id);
			}
		} else {
			LOG_WARN("server replied with invalid chain block [block id = %, tag = %] (%)", id, to_hex(block.tag()), impl_->config.log_id);
			//t: handle correctly
			// what to do here? try again or deem the server as bad behaving?
		}
	} else {
		LOG_INFO("committing failed: error=% (%)", res.get_error(), impl_->config.log_id);
		//t: handle correctly:
		//  1. bring us up-to-date with server state
		//  2. see if there are conflicts and notify higher level if there are
		//  3. recreate the records with correct previous tag/last seen seq for non-conflicting records
		//  4. try to commit again
	}
}

void sync_engine::on_data_uploaded(request_handle req_handle, std::optional<error>) {
	assert(not "implemented");
}

void sync_engine::on_record_received(chain_block const& block) {
	std::unique_lock lock{impl_->mutex};
	LOG_INFO("on_record_received (%)", impl_->config.log_id);
	impl_->handle_incoming_record(block);
}


//--- engine_input interface, see interface.hpp

//f: for now just implement plain record without data
record_handle sync_engine::sync_object_change(object_id oid, metadata mdata, record_data_handle) {
	std::unique_lock lock{impl_->mutex};
	LOG_TRACE("sync object change: oid=% (%)", oid.to_hex(), impl_->config.log_id);

	auto last_oid_record = impl_->records.find_last(oid);
	auto last_block = impl_->records.last_block();

	if(!last_block.is_valid()) {
		throw error(errc::invalid_record_chain_state, "Can't find last record, data change cannot be first record");
	}

	record_tag last_oid_tag = last_oid_record ? last_oid_record->tag() : record_tag{};

	data_change_record_creator creator(impl_->keys.current_key(), last_block);
	creator.add_change(std::move(oid), last_oid_tag, std::move(mdata));

	record_handle h = impl_->records.create(creator.result());
	//f: handle record data

	impl_->commit_record(h);

	return h;
}

record_handle sync_engine::sync_user_change(users user_change, metadata mdata) {
	std::unique_lock lock{impl_->mutex};
	LOG_TRACE("sync user change: users=% (%)", user_change, impl_->config.log_id);

	auto last_block = impl_->records.last_block();

	user_change_record_creator creator(impl_->keys.current_key(), last_block);

	creator.set_change(std::move(user_change), std::move(mdata));
	//todo: new encryption key here and such with the change

	record_handle h = impl_->records.create(creator.result());
	impl_->commit_record(h);

	return h;
}

record_handle sync_engine::sync_segment_end(metadata mdata) {
	std::unique_lock lock{impl_->mutex};
	LOG_TRACE("sync segment end (%)", impl_->config.log_id);

	auto last_block = impl_->records.last_block();

	if(!last_block.is_valid()) {
		throw error(errc::invalid_record_chain_state, "Can't find last record, segment cannot be first record");
	}

	segment_record_creator creator(impl_->keys.current_key(), last_block);

	//needs the start, end sequences and the record tags
	//creator.add_change(std::move(mdata));

	record_handle h = impl_->records.create(creator.result());
	impl_->commit_record(h);

	return h;
}

}
