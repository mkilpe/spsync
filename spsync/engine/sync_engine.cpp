#include "sync_engine.hpp"
#include "record_creator.hpp"
#include "record_verifier.hpp"
#include "types.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/protocol/types.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <map>
#include <mutex>

#define LTRACE(format, ...) LOG_TRACE(format " (rsid=%)" __VA_OPT__(,) __VA_ARGS__, config.log_id)
#define LINFO(format, ...) LOG_INFO(format " (rsid=%)" __VA_OPT__(,) __VA_ARGS__, config.log_id)
#define LWARN(format, ...) LOG_WARN(format " (rsid=%)" __VA_OPT__(,) __VA_ARGS__, config.log_id)

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
		request_handle req = comm.commit_record(h);
		LINFO("trying to commit record to server [tag = %, request handle = %]", to_hex(h->tag()), req);
	}

	void update_record_commit_state(record_handle h, chain_block const& record, chain_block_id const& id) {
		auto state = check_chain_block(record, id);
		if(record.check_matches_without_server_data(h->record()) && is_valid_state(state)) {
			LINFO("setting state for record [block id = %, parent block = %, tag = %, state = %]",
				id, to_hex(record.parent_hash()), to_hex(h->tag()), state);
			h->set_state(state, id, record.parent_hash());
		} else {
			h->set_state(record_state::invalid);

			//t: handle error, what to do?
			LWARN("Server returned invalid record [local tag=%, server tag=%]", to_hex(h->tag()), to_hex(record.tag()));
		}
	}

	void check_pending_records(chain_block_id id) {
		LTRACE("check_pending_records [id = %]", id);
		record_handle next;
		while((next = records.find(id.sequence+1, record_state::pending_sync))
			&& next->parent_block_hash() == id.hash)
		{
			id = next->block_id();
			LTRACE("setting pending sync to in sync state [id = %]", id);
			next->set_state(record_state::in_sync);
		}
		if(next && next->parent_block_hash() != id.hash) {
			LWARN("next block has invalid parent hash [id = %, next parent hash = %]", id, to_hex(next->parent_block_hash()));
		}
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
						LWARN("Record sequence does not match with its parent [block id = %, tag = %"
							", seq = %, parent seq = %, parent hash = %]"
							, id, to_hex(record.tag()), to_hex(record.parent_hash()), record.sequence()
							, parent->block_id().sequence);
					}
				} else {
					LTRACE("Record block with unknown parent [block id = %, tag = %, parent hash = %]"
						, id, to_hex(record.tag()), to_hex(record.parent_hash()));

					if(last_block.sequence+1 < record.sequence()) {
						// if the sequence is bigger than the next one we are waiting, then try this block later on when we
						// have the missing blocks in between.
						state = record_state::pending_sync;
					}
				}
			}
		} else {
			LWARN("Record block with sequence number that is already in use [block id = %, tag = %]"
				, id, to_hex(record.tag()));
		}

		LTRACE("check_chain_block returns state %", state);
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
				update_server_seq(record.sequence());
				if(handle_block_chain(record, id)) {
					check_pending_records(id);
					if(records.last_block().sequence == server_seq) {
						try_commit_pending();
					}
				}
			} else {
				LWARN("Record is not authentic [block id = %, tag = %]", id, to_hex(record.tag()));
			}
		} else {
			LINFO("No valid key for record [block id = %, tag = %, key id = %]", id, to_hex(record.tag()), rec.encryption_key());
			// store for later, when we hopefully have the key
			records.create(record, record_state::pending_sync);
		}
	}

	void handle_incoming_record(chain_block const& record) {
		chain_block_id id{record.id()};
		LINFO("received record block [block id = %, tag = %]", id, to_hex(record.tag()));

		if(id.is_valid()) {
			auto handle = records.find_tag(record.tag());
			if(!handle) {
				record.deserialise_record([&](auto const& rec) {
						this->handle_block(record, id, rec);
					});
			} else {
				LTRACE("record block already known [block id = %, tag = %]", id, to_hex(record.tag()));
			}
		} else {
			LWARN("server sent invalid record block");
		}
	}

	auth_record<data_change_record> update_record(encryption_key const& key, data_change_record_verifier& ver) const {
		auto last_block = records.last_block();
		LINFO("updating last block to %", last_block);
		data_change_record_creator creator(key, last_block);
		for(auto const& r : ver.headers()) {
			//f: conflict handling
			if(!r.data.previous_oid_record_tag.empty()) {
				LWARN("oid for out of sync not implemented");
				throw error(securepath::errc::not_implemented, "oid for out of sync not implemented");
			}

			creator.add_change(r.header, r.data);
		}
		return creator.result();
	}

	auth_record<user_change_record> update_record(encryption_key const& key, user_change_record_verifier& ver) const {
		auto last_block = records.last_block();
		LINFO("updating last block to %", last_block);
		user_change_record_creator creator(key, last_block);
		creator.set_data(ver.header(), ver.data());
		return creator.result();
	}

	auth_record<segment_record> update_record(encryption_key const& key, segment_record_verifier& ver) const {
		auto last_block = records.last_block();
		LINFO("updating last block to %", last_block);
		segment_record_creator creator(key, last_block);
		//f: implement
		return creator.result();
	}

	chain_block update_pending_commit(chain_block const& record) {
		return record.deserialise_record<chain_block>([&](auto const& rec) {
				auto enc_key = keys.find(rec.encryption_key());
				if(!enc_key) {
					LWARN("could not find encryption key for pending commit (key=%)", rec.encryption_key());
					throw error(errc::constraint_violation, "could not find encryption key for pending commit");
				}

				record_verifier<std::decay_t<decltype(rec)>> ver(*enc_key, rec, record.auth());
				if(!ver.is_authentic()) {
					throw make_error(errc::constraint_violation, "failed to authenticate record");
				}

				return update_record(*enc_key, ver);
			});
	}

	void try_commit_pending() {
		//t: can we optimise when we are trying to push commits again
		// ie. pushing currently even if we just did and something came in meanwhile
		LTRACE("trying to commit pending records");
		auto handle = records.find_first_pending_commit();
		if(handle) {
			auto record = update_pending_commit(handle->record());
			handle->set_record(record);
			commit_record(handle);
		}

	}

	void update_server_seq(sequence_number s) {
		if(s > server_seq) {
			LTRACE("biggest seen server sequence: %", s);
			server_seq = s;
		}
	}

public:
	mutable engine_mutex_type mutex;
	comm_input& comm;
	encryption_key_storage& keys;
	record_storage& records;
	sync_engine_config config;
	engine_output* output{};
	sequence_number server_seq;
};

// redefine to use the impl for normal members
#undef LTRACE
#undef LINFO
#undef LWARN
#define LTRACE(format, ...) LOG_TRACE(format " (rsid=%)" __VA_OPT__(,) __VA_ARGS__, impl_->config.log_id)
#define LINFO(format, ...) LOG_INFO(format " (rsid=%)" __VA_OPT__(,) __VA_ARGS__, impl_->config.log_id)
#define LWARN(format, ...) LOG_WARN(format " (rsid=%)" __VA_OPT__(,) __VA_ARGS__, impl_->config.log_id)

sync_engine::sync_engine(event_system::event_loop& loop, comm_input& comm, encryption_key_storage& keys, sync_engine_config config)
: comm_output(loop)
, impl_(std::make_unique<impl>(comm, keys, std::move(config)))
{
}

sync_engine::~sync_engine()
{
	 stop_handler();
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
void sync_engine::on_connected() {
	std::unique_lock lock{impl_->mutex};
	auto handle = impl_->comm.fetch_sequence_number();
	LTRACE("on_connected, requested sequence number (request handle %)", handle);
}

void sync_engine::on_disconnected(std::optional<error> err) {
	std::unique_lock lock{impl_->mutex};
	LTRACE("on_disconnected [error = %]", err.value_or(error()));
	// nothing for sync_engine
}

void sync_engine::on_sequence_number_response(request_handle req_handle, result<sequence_number> const& res) {
	std::unique_lock lock{impl_->mutex};
	if(res) {
		LINFO("on_sequence_number_response: % (request handle %)", res.value(), req_handle);
		impl_->update_server_seq(res.value());
		auto highest_seq = impl_->records.highest_sequence_number();
		if(highest_seq < res.value()) {
			// try to fetch all records we don't have
			auto req_h = impl_->comm.fetch_records(highest_seq, sequence_number{});
			LTRACE("requested records [%,-] (request handle %)", highest_seq, req_h);
		}
	} else {
		LINFO("on_sequence_number_response with error: % (request handle %)", res.get_error(), req_handle);
	}
}

void sync_engine::on_record_response(request_handle req_handle, record_response const& res) {
	std::unique_lock lock{impl_->mutex};
	LINFO("on_record_received (request handle = %, requested max = %, server seq = %)", req_handle, res.requested_max, res.server_max_sequence);
	if(res.data) {
		auto records = res.data.value();
		LTRACE("received % records", records.size());
		if(!records.empty()) {
			for(auto&& block : records) {
				impl_->handle_incoming_record(block);
			}
			sequence_number last_seq = records.back().sequence();
			if(last_seq < res.requested_max || (!res.requested_max.is_valid() && last_seq < res.server_max_sequence)) {
				auto req_h = impl_->comm.fetch_records(last_seq, res.requested_max);
				LTRACE("requested more records [%,%] (request handle %)", last_seq, res.requested_max, req_h);
			}
		}
	} else {
		LINFO("fetching records failed: error=%", res.data.get_error());
		//network error?
	}
}

void sync_engine::on_data_response(request_handle req_handle, result<record_data_handle> const&) {
	assert(not "implemented");
}

void sync_engine::on_commit_response(request_handle req_handle, commit_response const& res) {
	std::unique_lock lock{impl_->mutex};
	LINFO("on_commit_response [request handle = %]", req_handle);

	if(res.data) {
		auto block = res.data.value();
		chain_block_id id = block.id();

		if(id.is_valid()) {
			auto handle = impl_->records.find_tag(block.tag());
			if(handle) {
				impl_->update_record_commit_state(handle, block, id);
			} else {
				LWARN("commit reply with unknown tag [block id = %, tag = %]", id, to_hex(block.tag()));
			}
		} else {
			LWARN("server replied with invalid chain block [block id = %, tag = %]", id, to_hex(block.tag()));
			//t: handle correctly
			// what to do here? try again or deem the server as bad behaving?
		}
	} else {
		LINFO("committing failed: error=%", res.data.get_error());
		//t: handle correctly:
		//  1. bring us up-to-date with server state
		//  2. see if there are conflicts and notify higher level if there are
		//  3. recreate the records with correct previous tag/last seen seq for non-conflicting records
		//  4. try to commit again

		if(check_result_error(res.data, protocol::errc::record_out_of_sync)) {
			auto highest_seq = impl_->records.highest_sequence_number();
			if(highest_seq < res.server_max_sequence) {
				// try to fetch all records we don't have
				auto req_h = impl_->comm.fetch_records(highest_seq, sequence_number{});
				LTRACE("out of sync, requested records [%,-] (request handle %)", highest_seq, req_h);
			}
		}
	}
}

void sync_engine::on_data_uploaded(request_handle req_handle, std::optional<error>) {
	assert(not "implemented");
}

void sync_engine::on_record_received(chain_block const& block) {
	std::unique_lock lock{impl_->mutex};
	LINFO("on_record_received [seq = %]", block.sequence());
	impl_->handle_incoming_record(block);
}


//--- engine_input interface, see interface.hpp

//f: for now just implement plain record without data
record_handle sync_engine::sync_object_change(object_id oid, metadata mdata, record_data_handle) {
	std::unique_lock lock{impl_->mutex};
	LTRACE("sync object change: oid=%", oid.to_hex());

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
	LTRACE("sync user change: users=%", user_change);

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
	LTRACE("sync segment end");

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
