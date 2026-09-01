#include "sync_engine.hpp"
#include "record_creator.hpp"
#include "record_verifier.hpp"
#include "rebase_policy.hpp"
#include "types.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/protocol/types.hpp>
#include <spsync/protocol/error.hpp>

#include <securepath/log/log.hpp>
#include <securepath/util/conversions.hpp>

#include <algorithm>
#include <map>
#include <mutex>

#define LTRACE(format, ...) LOG_TRACE(format " (rsid={})" __VA_OPT__(,) __VA_ARGS__, config.log_id)
#define LINFO(format, ...) LOG_INFO(format " (rsid={})" __VA_OPT__(,) __VA_ARGS__, config.log_id)
#define LWARN(format, ...) LOG_WARN(format " (rsid={})" __VA_OPT__(,) __VA_ARGS__, config.log_id)

namespace securepath::sync {

class sync_engine::impl {
public:
	impl(comm_input& comm, crypto_context& cc, sync_engine_config config)
	: comm(comm)
	, crypto(cc)
	, records(comm.records())
	, config(std::move(config))
	{}

	request_handle commit_record(record_handle h) {
		if(fork_suspected) {
			LWARN("not committing, fork suspected for this storage [tag = {}]", to_hex(h->tag()));
			return request_handle{};
		}
		pushing_pending_commit = comm.commit_record(h);
		LINFO("trying to commit record to server [tag = {}, request handle = {}]", to_hex(h->tag()), pushing_pending_commit);
		return pushing_pending_commit;
	}

	void notify_on_record(record_handle h) {
		if(output) {
			auto tag = h->type();
			if(tag == user_change_record_tag) {
				output->emit<engine_events::on_user_changed>(h);
			} else if(tag == data_change_record_tag) {
				output->emit<engine_events::on_object_data_changed>(h);
			}
		}
	}

	void extract_encryption_key(chain_block const& rec) {
		auto user_change = rec.deserialise_to<user_change_record>();
		auto env_c = user_change.data().enveloped_content();
		if(!env_c.empty()) {
			try {
				//t: handle overwriting pending keys etc
				auto plain_env = serialisation::asn_der_deserialise<env_structure>(env_c.decrypt(my_private_key(crypto.private_data())));
				for(auto&& v : plain_env.enc_keys) {
					if(!crypto.enc_keys().find(v.key_seq)) {
						LINFO("saving not seen encryption key (seq={})", v.key_seq);
						crypto.enc_keys().insert(v);
					} else {
						LTRACE("already known encryption key (seq={})", v.key_seq);
					}
				}
			} catch(std::exception const& exp) {
				LWARN("exception while handling encryption key from user change record (tag={}, exp={})", to_hex(rec.tag()), exp.what());
			}
		}
	}

	void update_record_commit_state(record_handle h, chain_block const& record, chain_block_id const& id) {
		// a commit response is conceptually only an ack (record_state::acked); on a single
		// server acked is durable, so the record moves acked -> in_sync in the same step.
		// The replication work (plan phase 6) splits this into ack now, in_sync on commit.
		auto state = check_chain_block(record, id);
		if(record.check_matches_without_server_data(h->record()) && is_valid_state(state)) {
			LINFO("setting state for record [block id = {}, parent block = {}, tag = {}, state = {}]",
				id, to_hex(record.parent_hash()), to_hex(h->tag()), state);
			h->set_state(state, id, record.parent_hash());

			if(state == record_state::in_sync) {
				notify_on_record(h);
			}
		} else {
			h->set_state(record_state::invalid);

			//t: handle error, what to do?
			LWARN("Server returned invalid record [local tag={}, server tag={}]", to_hex(h->tag()), to_hex(record.tag()));
		}
	}

	void check_pending_records(chain_block_id id) {
		LTRACE("check_pending_records [id = {}]", id);
		record_handle next;
		while((next = records.find(id.sequence+1, record_state::pending_sync))
			&& next->parent_block_hash() == id.hash)
		{
			id = next->block_id();
			LTRACE("setting pending sync to in sync state [id = {}]", id);
			next->set_state(record_state::in_sync);
			notify_on_record(next);
		}
		if(next && next->parent_block_hash() != id.hash) {
			LWARN("next block has invalid parent hash [id = {}, next parent hash = {}]", id, to_hex(next->parent_block_hash()));
		}
	}

	record_state check_chain_block(chain_block const& record, chain_block_id const& id) {
		record_state state = config.mode == sync_mode::require_all_seen
			? check_chain_block_strict(record, id)
			: check_chain_block_weak(record, id);
		LTRACE("check_chain_block returns state {}", state);
		return state;
	}

	/**
	 * Weak modes do not require a contiguous local chain: the server sequence is only a
	 * cursor and the parent hash is informative. A block is acceptable when no different
	 * block is already in sync for its sequence; gaps and out of order arrival are fine.
	 */
	record_state check_chain_block_weak(chain_block const& record, chain_block_id const& id) {
		record_state state = record_state::invalid;
		auto existing = records.find(record.sequence());
		if(!existing) {
			state = record_state::in_sync;
		} else {
			LWARN("different record block already in sync for the sequence [block id = {}, tag = {}, existing tag = {}]"
				, id, to_hex(record.tag()), to_hex(existing->tag()));
		}
		return state;
	}

	record_state check_chain_block_strict(chain_block const& record, chain_block_id const& id) {
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
						LWARN("Record sequence does not match with its parent [block id = {}, tag = {}"
							", seq = {}, parent seq = {}, parent hash = {}]"
							, id, to_hex(record.tag()), to_hex(record.parent_hash()), record.sequence()
							, parent->block_id().sequence);
					}
				} else {
					LTRACE("Record block with unknown parent [block id = {}, tag = {}, parent hash = {}]"
						, id, to_hex(record.tag()), to_hex(record.parent_hash()));

					if(last_block.sequence+1 < record.sequence()) {
						// if the sequence is bigger than the next one we are waiting, then try this block later on when we
						// have the missing blocks in between.
						state = record_state::pending_sync;
					}
				}
			}
		} else {
			LWARN("Record block with sequence number that is already in use [block id = {}, tag = {}]"
				, id, to_hex(record.tag()));
		}

		return state;
	}

	bool handle_block_chain(chain_block const& record, chain_block_id const& id) {
		auto state = check_chain_block(record, id);
		record_handle h = records.create(record, state);
		if(state == record_state::in_sync) {
			notify_on_record(h);
		}
		return state == record_state::in_sync;
	}

	/**
	 * Strict mode cross-check of the authenticated back reference (plan 2.6): the record's
	 * author saw a different block than we hold in sync for the same sequence - the server
	 * showed two histories. Emitted once; commits to this storage stop (D10).
	 * Weak modes get a tag based variant with phase 4.3.
	 */
	template<typename Record>
	void check_fork(chain_block const& record, Record const& rec) {
		if(config.mode == sync_mode::require_all_seen && !fork_suspected) {
			auto const& ls = rec.last_seen_block();
			if(ls.is_valid()) {
				auto ours = records.find(ls.sequence);
				if(ours && ours->block_id().hash != ls.hash) {
					fork_suspected = true;
					LWARN("fork suspected: incoming record refers to a different block for sequence {} [ours = {}, referred = {}]"
						, ls.sequence, to_hex(ours->block_id().hash), to_hex(ls.hash));
					if(output) {
						output->emit<engine_events::on_fork_suspected>(ours, record);
					}
				}
			}
		}
	}

	template<typename Record>
	void verify_block(encryption_key const& enc_key, chain_block const& record, chain_block_id const& id, Record const& rec) {
		record_verifier<Record> ver(enc_key, rec, record.auth());
		if(ver.is_authentic()) {
			check_fork(record, rec);
			update_server_seq(record.sequence());
			if(handle_block_chain(record, id)) {
				check_pending_records(id);
				if(records.last_block().sequence == server_seq) {
					try_commit_pending();
				}
			}
		} else {
			LWARN("Record is not authentic [block id = {}, tag = {}]", id, to_hex(record.tag()));
			//q: save the invalid record or not?
			//records.create(record, record_state::invalid);
		}
	}

	template<typename Record>
	void handle_block(chain_block const& record, chain_block_id const& id, Record const& rec) {
		auto enc_key = crypto.enc_keys().find(rec.encryption_key());
		if(enc_key) {
			verify_block(*enc_key, record, id, rec);
		} else {
			auto last_block = records.last_block();
			if(last_block.sequence == sequence_number{} && record.sequence() == sequence_number{1}) {
				LTRACE("first record, attempting to extract encryption key");
				//t: optional check of the tag of the first record (i.e. if given from above)
				//this is first record, try to extract enc key
				extract_encryption_key(record);
				auto enc_key = crypto.enc_keys().find(rec.encryption_key());
				if(enc_key) {
					verify_block(*enc_key, record, id, rec);
				} else {
					LINFO("Failed to extract encryption key from first record");
					records.create(record, record_state::pending_sync);
				}
			} else {
				LINFO("No valid key for record [block id = {}, tag = {}, key id = {}]", id, to_hex(record.tag()), rec.encryption_key());
				// store for later, when we hopefully have the key
				records.create(record, record_state::pending_sync);
			}
		}
	}

	bool is_structurally_valid(chain_block const& record) const {
		// check we have signature if such is required
		return config.auth_mode != auth_mode::sign_records || record.auth().has_signature();
	}

	/// our own pending record the server committed in an earlier form: same op id,
	/// different tag (the response of the original commit lost a race with a rebase)
	record_handle find_pending_by_op(chain_block const& record) const {
		auto op = record.deserialise_record<octet_vector>([](auto const& rec){ return rec.op_id(); });
		record_handle h;
		if(!op.empty()) {
			h = records.find_op_id(op);
			if(h && h->state() != record_state::pending_commit) {
				h = nullptr;
			}
		}
		return h;
	}

	void adopt_committed(record_handle h, chain_block const& record, chain_block_id const& id) {
		LINFO("adopting committed form of own pending record [block id = {}, tag = {}]", id, to_hex(record.tag()));
		auto state = check_chain_block(record, id);
		if(is_valid_state(state)) {
			h->set_record(record);
			h->set_state(state, id, record.parent_hash());
			if(state == record_state::in_sync) {
				notify_on_record(h);
			}
		}
	}

	void handle_incoming_record(chain_block const& record, std::optional<block_envelope> const& envelope = {}) {
		chain_block_id id{record.id()};
		LINFO("received record block [block id = {}, tag = {}]", id, to_hex(record.tag()));

		if(id.is_valid() && is_structurally_valid(record)) {
			auto handle = records.find_tag(record.tag());
			if(!handle) {
				if(auto own = find_pending_by_op(record)) {
					adopt_committed(own, record, id);
				} else {
					record.deserialise_record([&](auto const& rec) {
							this->handle_block(record, id, rec);
						});
				}
			} else {
				LTRACE("record block already known [block id = {}, tag = {}]", id, to_hex(record.tag()));
			}
			if(envelope) {
				// keep the server signed assignment with the record (equivocation evidence)
				if(auto h = records.find_tag(record.tag())) {
					h->set_assignment(serialisation::asn_der_serialise(*envelope));
				}
			}
		} else {
			LWARN("server sent invalid record block");
		}
	}

	auth_record<data_change_record> update_record(encryption_key const& key, data_change_record_verifier& ver) const {
		auto last_block = records.last_block();
		LINFO("updating last block to {}", last_block);

		std::optional<crypto::private_key> signer;
		if(config.auth_mode == auth_mode::sign_records) {
			signer = my_private_key(crypto.private_data());
		}

		data_change_record_creator creator(key, last_block, signer, ver.base().op_id());
		for(auto const& r : ver.headers()) {
			auto data = r.data;
			if(!data.previous_oid_record_tag.empty()) {
				auto current = records.find_last(data.id);
				if(current && current->tag() != data.previous_oid_record_tag) {
					// the object changed underneath us: rebase this change on top of the
					// newest record (last writer wins)
					LINFO("rebasing conflicting object change [oid={}, previous={}, current={}]"
						, data.id, to_hex(data.previous_oid_record_tag), to_hex(current->tag()));
					data.previous_oid_record_tag = current->tag();
				}
			}
			creator.add_change(r.header, data);
		}
		return creator.result();
	}

	auth_record<user_change_record> update_record(encryption_key const& key, user_change_record_verifier& ver) const {
		auto last_block = records.last_block();
		LINFO("updating last block to {}", last_block);

		std::optional<crypto::private_key> signer;
		if(config.auth_mode == auth_mode::sign_records) {
			signer = my_private_key(crypto.private_data());
		}

		user_change_record_creator creator(key, last_block, signer, ver.base().op_id());
		creator.set_data(ver.header(), ver.data());
		return creator.result();
	}

	/**
	 * Build the plain segment data for a segment committed on top of base: it covers
	 * [previous segment end (else 1), base sequence + 1) with the in sync tags of that
	 * range, linking the previous segment by tag (segments.txt S1/S2). The previous
	 * segment itself is the first covered record, so every record is covered exactly once.
	 */
	plain_segment_data make_segment_data(chain_block_id const& base) const {
		sequence_number start{1};
		record_tag previous_tag;
		if(auto previous = records.find_last_of_type(segment_record_tag)) {
			previous_tag = previous->tag();
			start = previous->record().deserialise_to<segment_record>().data().segment_end();
		}
		return plain_segment_data{start, base.sequence + 1
			, records.tags_in_range(start, base.sequence), std::move(previous_tag)};
	}

	auth_record<segment_record> update_record(encryption_key const& key, segment_record_verifier& ver) const {
		auto last_block = records.last_block();
		LINFO("updating last block to {}", last_block);

		std::optional<crypto::private_key> signer;
		if(config.auth_mode == auth_mode::sign_records) {
			signer = my_private_key(crypto.private_data());
		}

		segment_record_creator creator(key, last_block, signer, ver.base().op_id());
		// the covered range moved underneath the segment: recompute the end and the tag
		// list from the storage, keeping the caller's header (metadata, creation time)
		creator.set_data(ver.header(), make_segment_data(last_block));
		return creator.result();
	}

	chain_block update_pending_commit(chain_block const& record) {
		return record.deserialise_record<chain_block>([&](auto const& rec) {
				//check if we are already trying to commit pending record, so that we don't overwrite it while in progress
				if(rec.last_seen_block() == records.last_block()) {
					// already up-to-date it seems
					return chain_block{};
				}

				auto enc_key = crypto.enc_keys().find(rec.encryption_key());
				if(!enc_key) {
					LWARN("could not find encryption key for pending commit (key={})", rec.encryption_key());
					throw error(errc::no_encryption_key_found, "could not find encryption key for pending commit");
				}

				record_verifier<std::decay_t<decltype(rec)>> ver(*enc_key, rec, record.auth());
				if(!ver.is_authentic()) {
					throw make_error(errc::not_authentic, "failed to authenticate record");
				}

				return chain_block{update_record(*enc_key, ver)};
			});
	}

	/**
	 * The block new records are based on: strict mode stacks pending commits (they are
	 * rebased as needed), weak modes base records on the confirmed head. Falls back to
	 * pending commits only when there is no confirmed block yet (bootstrap).
	 */
	chain_block_id base_block() const {
		auto b = records.last_block(config.mode == sync_mode::require_all_seen);
		if(!b.is_valid()) {
			b = records.last_block(true);
		}
		return b;
	}

	/// mode-aware check whether the pending record has to be rebuilt before committing
	bool pending_needs_rebase(chain_block const& record) const {
		return record.deserialise_record<bool>([&](auto const& rec) {
				rebase_state state;
				state.mode = config.mode;
				state.type = std::decay_t<decltype(rec)>::tag;
				if constexpr(std::is_same_v<std::decay_t<decltype(rec)>, data_change_record>) {
					state.has_adds = std::ranges::any_of(rec, [](auto const& c) {
							return c.data.previous_oid_record_tag.empty();
						});
				}
				state.last_seen = rec.last_seen_block();
				state.head = records.last_block();
				state.last_special = records.last_special_sequence();
				state.last_data_add = records.last_data_add_sequence();
				return needs_rebase(state);
			});
	}

	/// the newest records of objects that changed underneath the pending record
	std::deque<record_handle> find_oid_conflicts(chain_block const& record) const {
		std::deque<record_handle> conflicts;
		record.deserialise_record([&](auto const& rec) {
				if constexpr(std::is_same_v<std::decay_t<decltype(rec)>, data_change_record>) {
					for(auto const& c : rec) {
						if(!c.data.previous_oid_record_tag.empty()) {
							auto current = records.find_last(c.data.id);
							if(current && current->tag() != c.data.previous_oid_record_tag) {
								conflicts.push_back(current);
							}
						}
					}
				}
			});
		return conflicts;
	}

	void notify_conflicts(record_handle local, std::deque<record_handle> const& conflicts) {
		if(output) {
			for(auto&& remote : conflicts) {
				output->emit<engine_events::on_object_conflict>(local, remote);
			}
		}
	}

	/// cancel the pending record because of the ask policy; the higher layer decides
	void cancel_conflicting(record_handle handle, std::deque<record_handle> const& conflicts) {
		LINFO("cancelling conflicting pending record [tag={}]", to_hex(handle->tag()));
		handle->set_state(record_state::invalid);
		notify_conflicts(handle, conflicts);
	}

	void try_commit_pending() {
		if(!pushing_pending_commit && !fork_suspected) {
			//t: can we optimise when we are trying to push commits again
			// ie. pushing currently even if we just did and something came in meanwhile
			LTRACE("trying to commit pending records");
			auto handle = records.find_first_pending_commit();
			for(; handle;) {
				auto conflicts = find_oid_conflicts(handle->record());
				if(!conflicts.empty() && config.conflicts == conflict_policy::ask) {
					cancel_conflicting(handle, conflicts);
					// the cancelled record is invalid now, move on to the next pending one
					handle = records.find_first_pending_commit();
				} else {
					if(!conflicts.empty() || pending_needs_rebase(handle->record())) {
						auto record = update_pending_commit(handle->record());
						if(record.is_valid()) {
							handle->set_record(record);
						}
						notify_conflicts(handle, conflicts);
					}
					//t: avoid recommitting unchanged records the server has already rejected
					commit_record(handle);
					handle = nullptr;
				}
			}
		}
	}

	void update_server_seq(sequence_number s) {
		if(s > server_seq) {
			LTRACE("biggest seen server sequence: {}", s);
			server_seq = s;
		}
	}

public:
	mutable engine_mutex_type mutex;
	comm_input& comm;
	crypto_context& crypto;
	record_storage& records;
	sync_engine_config config;
	engine_output* output{};
	sequence_number server_seq;
	// if we have ongoing committing going for pending record
	request_handle pushing_pending_commit{};
	// set when the server is suspected of showing two histories; commits stop (plan 2.6)
	bool fork_suspected{};
};

// redefine to use the impl for normal members
#undef LTRACE
#undef LINFO
#undef LWARN
#define LTRACE(format, ...) LOG_TRACE(format " (rsid={})" __VA_OPT__(,) __VA_ARGS__, impl_->config.log_id)
#define LINFO(format, ...) LOG_INFO(format " (rsid={})" __VA_OPT__(,) __VA_ARGS__, impl_->config.log_id)
#define LWARN(format, ...) LOG_WARN(format " (rsid={})" __VA_OPT__(,) __VA_ARGS__, impl_->config.log_id)

namespace {

void check_engine_config(sync_engine_config const& config) {
	if(!valid_storage_modes(storage_modes{config.mode, config.auth_mode, config.replication})) {
		throw make_error(errc::invalid_configuration, "replicated storage requires sign_records");
	}
}

}

sync_engine::sync_engine(event_system::event_loop& loop, comm_input& comm, crypto_context& cc, sync_engine_config config)
: comm_output(loop)
, impl_((check_engine_config(config), std::make_unique<impl>(comm, cc, std::move(config))))
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
	check_engine_config(config);
	std::unique_lock lock{impl_->mutex};
	impl_->config = std::move(config);
}


//--- comm_output interface, see comm/interface.hpp
void sync_engine::on_connected() {
	std::unique_lock lock{impl_->mutex};
	impl_->pushing_pending_commit = 0;
	auto handle = impl_->comm.fetch_sequence_number();
	LTRACE("on_connected, requested sequence number (request handle {})", handle);
}

void sync_engine::on_disconnected(std::optional<error> err) {
	std::unique_lock lock{impl_->mutex};
	impl_->pushing_pending_commit = 0;
	LTRACE("on_disconnected [error = {}]", err.value_or(error()));
	// nothing for sync_engine
}

void sync_engine::on_sequence_number_response(request_handle req_handle, result<sequence_number> const& res) {
	std::unique_lock lock{impl_->mutex};
	if(res) {
		LINFO("on_sequence_number_response: {} (request handle {})", res.value(), req_handle);
		impl_->update_server_seq(res.value());
		auto highest_seq = impl_->records.highest_sequence_number();
		if(highest_seq < res.value()) {
			// try to fetch all records we don't have
			auto req_h = impl_->comm.fetch_records(highest_seq, sequence_number{});
			LTRACE("requested records [{},-] (request handle {})", highest_seq, req_h);
		} else {
			//already up-to-date with server but perhaps we have some local pending commits
			impl_->try_commit_pending();
		}
	} else {
		LINFO("on_sequence_number_response with error: {} (request handle {})", res.get_error(), req_handle);
	}
}

void sync_engine::on_record_response(request_handle req_handle, record_response const& res) {
	std::unique_lock lock{impl_->mutex};
	LINFO("on_record_received (request handle = {}, requested max = {}, server seq = {})", req_handle, res.requested_max, res.server_max_sequence);
	if(res.data) {
		auto records = res.data.value();
		LTRACE("received {} records", records.size());
		if(!records.empty()) {
			for(auto&& block : records) {
				impl_->handle_incoming_record(block);
			}
			sequence_number last_seq = records.back().sequence();
			if(last_seq < res.requested_max || (!res.requested_max.is_valid() && last_seq < res.server_max_sequence)) {
				auto req_h = impl_->comm.fetch_records(last_seq, res.requested_max);
				LTRACE("requested more records [{},{}] (request handle {})", last_seq, res.requested_max, req_h);
			}
		}
	} else {
		LINFO("fetching records failed: error={}", res.data.get_error());
		//network error?
	}
}

void sync_engine::on_data_response(request_handle req_handle, result<record_data_handle> const&) {
	assert(not "implemented");
}

void sync_engine::on_commit_response(request_handle req_handle, commit_response const& res) {
	std::unique_lock lock{impl_->mutex};
	LINFO("on_commit_response [request handle = {}]", req_handle);

	if(req_handle == impl_->pushing_pending_commit) {
		LTRACE("clearing pending commit request handle [{}]", req_handle);
		impl_->pushing_pending_commit = 0;
	}

	if(res.data) {
		auto block = res.data.value();
		chain_block_id id = block.id();

		if(id.is_valid()) {
			auto handle = impl_->records.find_tag(block.tag());
			if(handle) {
				impl_->update_record_commit_state(handle, block, id);
				if(res.envelope) {
					handle->set_assignment(serialisation::asn_der_serialise(*res.envelope));
				}
				impl_->try_commit_pending();
			} else {
				LWARN("commit reply with unknown tag [block id = {}, tag = {}]", id, to_hex(block.tag()));
			}
		} else {
			LWARN("server replied with invalid chain block [block id = {}, tag = {}]", id, to_hex(block.tag()));
			//t: handle correctly
			// what to do here? try again or deem the server as bad behaving?
		}
	} else {
		LINFO("committing failed: error={}", res.data.get_error());
		//t: handle correctly:
		//  + 1. bring us up-to-date with server state
		//  - 2. see if there are conflicts and notify higher level if there are
		//  + 3. recreate the records with correct previous tag/last seen seq for non-conflicting records
		//  + 4. try to commit again

		if(check_result_error(res.data, protocol::errc::record_out_of_sync)) {
			auto highest_seq = impl_->records.highest_sequence_number();
			if(highest_seq < res.server_max_sequence) {
				// try to fetch all records we don't have
				auto req_h = impl_->comm.fetch_records(highest_seq, sequence_number{});
				LTRACE("out of sync, requested records [{},-] (request handle {})", highest_seq, req_h);
			} else {
				//already up-to-date with server but perhaps we have some local pending commits
				impl_->try_commit_pending();
			}
		} else if(check_result_error(res.data, protocol::errc::record_already_committed)) {
			impl_->try_commit_pending();
		}
	}
}

void sync_engine::on_data_uploaded(request_handle req_handle, std::optional<error>) {
	assert(not "implemented");
}

void sync_engine::on_record_received(chain_block const& block, std::optional<block_envelope> const& envelope) {
	std::unique_lock lock{impl_->mutex};
	LINFO("on_record_received [seq = {}]", block.sequence());
	impl_->handle_incoming_record(block, envelope);
}


//--- engine_input interface, see interface.hpp

//f: for now just implement plain record without data
record_handle sync_engine::sync_object_change(object_id oid, metadata mdata, record_data_handle) {
	std::unique_lock lock{impl_->mutex};
	LTRACE("sync object change: oid={}", oid.to_hex());

	auto last_oid_record = impl_->records.find_last(oid);
	auto last_block = impl_->base_block();

	if(!last_block.is_valid()) {
		throw error(errc::invalid_record_chain_state, "Can't find last record, data change cannot be first record");
	}

	record_tag last_oid_tag = last_oid_record ? last_oid_record->tag() : record_tag{};

	std::optional<crypto::private_key> signer;
	if(impl_->config.auth_mode == auth_mode::sign_records) {
		signer = my_private_key(impl_->crypto.private_data());
	}
	data_change_record_creator creator(impl_->crypto.enc_keys().current_key(), last_block, signer);
	creator.add_change(std::move(oid), last_oid_tag, std::move(mdata));

	record_handle h = impl_->records.create(creator.result());
	//f: handle record data

	impl_->commit_record(h);

	return h;
}

record_handle sync_engine::sync_user_change(plain_user_change_data change_data, metadata mdata) {
	std::unique_lock lock{impl_->mutex};
	LTRACE("sync user change: users={}", change_data.access());

	auto last_block = impl_->base_block();

	std::optional<crypto::private_key> signer;
	if(impl_->config.auth_mode == auth_mode::sign_records) {
		signer = my_private_key(impl_->crypto.private_data());
	}
	user_change_record_creator creator(impl_->crypto.enc_keys().current_key(), last_block, signer);
	creator.set_change(std::move(change_data), std::move(mdata));

	record_handle h = impl_->records.create(creator.result());
	impl_->commit_record(h);

	return h;
}

record_handle sync_engine::sync_segment_end(metadata mdata) {
	std::unique_lock lock{impl_->mutex};
	LTRACE("sync segment end");

	auto last_block = impl_->base_block();

	if(!last_block.is_valid()) {
		throw error(errc::invalid_record_chain_state, "Can't find last record, segment cannot be first record");
	}
	// the tag list is built from the in sync records, so the seal is only exact when
	// nothing local is still waiting; the app commits its changes first
	if(impl_->records.find_first_pending_commit()) {
		throw error(errc::invalid_record_chain_state, "segment requires all local changes to be committed");
	}

	std::optional<crypto::private_key> signer;
	if(impl_->config.auth_mode == auth_mode::sign_records) {
		signer = my_private_key(impl_->crypto.private_data());
	}
	segment_record_creator creator(impl_->crypto.enc_keys().current_key(), last_block, signer);
	creator.set_change(impl_->make_segment_data(last_block), std::move(mdata));

	record_handle h = impl_->records.create(creator.result());
	impl_->commit_record(h);

	return h;
}

util::result<history_verify_report> sync_engine::verify_history() const {
	std::unique_lock lock{impl_->mutex};
	LTRACE("verify history");
	return sync::verify_history(impl_->records, impl_->crypto.enc_keys(), impl_->config.verification);
}

}
