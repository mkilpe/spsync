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
	{
		// the limits learned on an earlier attach (RDS 8); zero until then
		limits = records.limits();
	}

	/// the server reported the storage's limits with the attach answer: learn them once,
	/// they are immutable - a different report afterwards is a misconfigured replica
	void learn_limits(storage_limits const& reported) {
		if(reported.max_record_size != 0) {
			if(limits.max_record_size == 0) {
				LINFO("storage limits learned [max_record_size={}, chunk_size={}]", reported.max_record_size, reported.chunk_size);
				limits = reported;
				records.set_limits(reported);
			} else if(limits != reported) {
				LWARN("server reports other limits than the storage has [reported max_record_size={}, chunk_size={}; stored {}, {}]",
					reported.max_record_size, reported.chunk_size, limits.max_record_size, limits.chunk_size);
			}
		}
	}

	/**
	 * The storage's validity limits as the server reported them (RDS 8): an oversized
	 * change is refused here instead of being rejected by every replica after the fact.
	 * Unknown (0) until the first sequence answer, then no check.
	 */
	template<typename Record>
	void check_record_size(auth_record<Record> const& rec) const {
		if(limits.max_record_size != 0) {
			chain_block block{rec};
			if(block.record_bytes().size() > limits.max_record_size) {
				LWARN("record too big [size={}, limit={}]", block.record_bytes().size(), limits.max_record_size);
				throw error(errc::record_too_big, "record exceeds the storage's max_record_size");
			}
		}
	}

	request_handle commit_record(record_handle h) {
		if(fork_suspected) {
			LWARN("not committing, fork suspected for this storage [tag = {}]", to_hex(h->tag()));
			return request_handle{};
		}
		pushing_pending_commit = comm.commit_record(h);
		// several commits can be in flight (every sync_* call commits right away): the
		// response is matched to its record by request handle, not by "the last one"
		in_flight_commits[pushing_pending_commit] = h->tag();
		LINFO("trying to commit record to server [tag = {}, request handle = {}]", to_hex(h->tag()), pushing_pending_commit);
		return pushing_pending_commit;
	}

	/// the tag the commit request carried; empty when unknown (e.g. after a reconnect)
	record_tag take_in_flight(request_handle handle) {
		record_tag tag;
		auto it = in_flight_commits.find(handle);
		if(it != in_flight_commits.end()) {
			tag = it->second;
			in_flight_commits.erase(it);
		}
		return tag;
	}

	/**
	 * Where a fetch continues from: the record before the first gap in the received
	 * sequences, else the highest received one. A fetch interrupted by a lost connection
	 * or a replica hop leaves a gap that weak modes accept but must still fill (plan 4.5);
	 * after a history cut the retained records below the trusted anchor stay sparse.
	 */
	sequence_number fetch_cursor() const {
		sequence_number from{1};
		if(!config.trusted_anchor.empty()) {
			if(auto anchor = records.find(config.trusted_anchor)) {
				from = anchor->block_id().sequence;
			}
		}
		auto const gap = records.first_missing_sequence(from);
		return gap.is_valid() ? sequence_number{gap.value - 1} : records.highest_sequence_number();
	}

	/// fetch everything after the cursor when the server is ahead; false when up to date
	bool fetch_missing(std::string_view why) {
		auto const cursor = fetch_cursor();
		bool const behind = cursor < server_seq;
		if(behind) {
			auto req_h = comm.fetch_records(cursor, sequence_number{});
			LTRACE("{}, requested records [{},-] (request handle {})", why, cursor, req_h);
		}
		return behind;
	}

	/**
	 * The server rejected the outstanding commit and there is nothing to fetch that could
	 * change the picture: remember the record as rejected in its current form so
	 * try_commit_pending does not resend it unchanged (the M3 runs found both the
	 * already-committed and the out-of-sync retry storms). A rebase changes the record's
	 * hash and lifts the mark; new records, a completed fetch and a reconnect clear all.
	 */
	void mark_rejected(record_tag const& tag, bool duplicate) {
		if(!tag.empty()) {
			if(auto h = records.find_tag(tag)) {
				rejected_pending[tag] = rejection{h->record().hash(), duplicate};
			}
		}
	}

	/**
	 * Already committed: the server holds the tag, or the same op under another tag.
	 * Fetching what we miss confirms or adopts it, a blind recommit would only be
	 * rejected again.
	 */
	void on_duplicate_rejected(record_tag const& tag) {
		mark_rejected(tag, true);
		if(!fetch_missing("pending record already committed")) {
			// nothing to fetch: whatever the server holds under this op is here already
			resolve_rejected_duplicates();
			try_commit_pending();
		}
	}

	/// out of sync with nothing to fetch: a rebase (try_commit_pending) is the only way on
	void on_out_of_sync_rejected(record_tag const& tag) {
		if(!fetch_missing("out of sync")) {
			mark_rejected(tag, false);
			try_commit_pending();
		}
	}

	/// drop rejected duplicates whose committed twin (same op) we hold; the rest stay marked
	void resolve_rejected_duplicates() {
		for(auto it = rejected_pending.begin(); it != rejected_pending.end();) {
			auto h = records.find_tag(it->first);
			bool resolved = !h || h->state() != record_state::pending_commit;
			if(!resolved && it->second.duplicate) {
				auto op = h->record().deserialise_record<octet_vector>([](auto const& rec){ return rec.op_id(); });
				auto twin = op.empty() ? record_handle{} : records.find_op_id(op);
				if(twin && twin != h && is_server_confirmed(twin->state())) {
					LWARN("dropping pending record committed under another tag [tag = {}, committed tag = {}]",
						to_hex(h->tag()), to_hex(twin->tag()));
					h->set_state(record_state::invalid);
					resolved = true;
				} else {
					LWARN("server holds pending record as committed but its copy is unknown here [tag = {}]", to_hex(h->tag()));
				}
			}
			it = resolved ? rejected_pending.erase(it) : std::next(it);
		}
	}

	/// something changed in the server side view: every rejected pending gets another try
	void clear_rejections() {
		rejected_pending.clear();
	}

	/// the fetch chain ended: every rejected pending had its chance to be confirmed or adopted
	void on_fetch_complete() {
		if(!rejected_pending.empty()) {
			clear_rejections();
			try_commit_pending();
		}
	}

	/// rejected by the server in exactly this form: sending it again would say nothing new
	bool is_rejected_unchanged(record_handle const& h) const {
		auto it = rejected_pending.find(h->tag());
		return it != rejected_pending.end() && it->second.hash == h->record().hash();
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

	/// extract the keys a user change carries in its per-member KEM envelope; returns true
	/// when a not yet known key was added. The envelope is decrypted with our KEM private
	/// key, independent of the AES record key and of chain order, so a rotated key can be
	/// learned even before the record that uses it (plan 4.6)
	bool extract_encryption_key(chain_block const& rec) {
		auto const carrier_tag = rec.tag();
		auto user_change = rec.deserialise_to<user_change_record>();
		auto env_c = user_change.data().enveloped_content();
		bool learned = false;
		if(!env_c.empty()) {
			try {
				auto plain_env = serialisation::asn_der_deserialise<env_structure>(env_c.decrypt(my_private_key(crypto.private_data())));
				for(auto&& v : plain_env.enc_keys) {
					// keys are unioned (D9): a colliding sequence keeps both keys and
					// the insert ignores an identical one
					if(crypto.enc_keys().find_all(v.key_seq).empty()) {
						learned = true;
					}
					LTRACE("saving encryption key (seq={})", v.key_seq);
					crypto.enc_keys().insert(v, carrier_tag);
				}
			} catch(std::exception const& exp) {
				LTRACE("could not extract keys from user change (not a member or wrong key) [tag={}, exp={}]", to_hex(rec.tag()), exp.what());
			}
		}
		return learned;
	}

	void update_record_commit_state(record_handle h, chain_block const& record, chain_block_id const& id) {
		if(h->state() == record_state::in_sync || h->state() == record_state::acked) {
			// already confirmed: the server's record push can beat the commit response
			// (it is sent first) and the pending adoption confirmed the record there
			LTRACE("commit response for an already confirmed record [block id = {}]", id);
			return;
		}
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

	/**
	 * Chain acceptance around a trusted anchor (segments plan SEG 5): the anchor block
	 * itself starts the chain after a history cut, and the retained records below it are
	 * accepted content authenticated with an advisory position - the cut kept only the
	 * anchor as positional proof.
	 */
	std::optional<record_state> check_anchor_chain_block(chain_block const& record) {
		std::optional<record_state> state;
		if(!config.trusted_anchor.empty() && !records.find(record.sequence())) {
			if(record.hash() == config.trusted_anchor) {
				LINFO("accepting the trusted anchor as the chain start [seq = {}]", record.sequence());
				state = record_state::in_sync;
			} else {
				auto anchor = records.find(config.trusted_anchor);
				if(anchor && record.sequence() < anchor->block_id().sequence) {
					state = record_state::in_sync;
				}
			}
		}
		return state;
	}

	/**
	 * Retained records that arrived before the anchor wait in pending_sync; once the
	 * anchor block is in sync their content stands on its own (SEG 5)
	 */
	void promote_pre_anchor_records(chain_block_id const& id) {
		if(!config.trusted_anchor.empty() && id.hash == config.trusted_anchor) {
			for(auto const& h : records.find_range(sequence_number{1}, id.sequence - 1, record_state::pending_sync)) {
				LTRACE("promoting retained pre-anchor record [id = {}]", h->block_id());
				h->set_state(record_state::in_sync);
				notify_on_record(h);
			}
		}
	}

	record_state check_chain_block_strict(chain_block const& record, chain_block_id const& id) {
		// needs to fulfil:
		//  parent.seq + 1 == record.sequence()
		//  parent.hash == record.parent_hash
		//  last_record.seq < record.sequence();

		if(auto anchor_state = check_anchor_chain_block(record)) {
			return *anchor_state;
		}

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
							, id, to_hex(record.tag()), record.sequence(), parent->block_id().sequence
							, to_hex(record.parent_hash()));
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
		if(config.mode != sync_mode::require_all_seen) {
			// the weak-mode cross-check is tag existence only (plan 4.3): an unknown
			// special reference is inconclusive - the record may simply arrive before it
			if(!rec.last_seen_special_tag().empty() && !records.find_tag(rec.last_seen_special_tag())) {
				LTRACE("special reference not yet known [tag = {}]", to_hex(rec.last_seen_special_tag()));
			}
		}
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
				promote_pre_anchor_records(id);
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

	/**
	 * The key of the record's key sequence that authenticates it. Usually the single
	 * stored key; concurrent key rotations can collide on a sequence with different
	 * keys (D9: both are kept) and then every candidate is tried (plan 4.6).
	 */
	template<typename Record>
	std::optional<encryption_key> find_record_key(Record const& rec, chain_block const& record) const {
		std::optional<encryption_key> ret;
		// try each key stored for the sequence and return the one that authenticates the
		// record; concurrent key rotations leave several keys at one sequence and only one
		// is right for a given record (plan 4.6/D9). Returns nullopt when none matches
		// (e.g. the record's key is not learned yet), keeping callers off a wrong key.
		for(auto const& key : crypto.enc_keys().find_all(rec.encryption_key())) {
			if(!ret) {
				try {
					record_verifier<Record> ver(key, rec, record.auth());
					if(ver.is_authentic()) {
						ret = key;
					}
				} catch(std::exception const&) {
					// a wrong candidate decrypts garbage that fails to parse
				}
			}
		}
		return ret;
	}

	template<typename Record>
	void handle_block(chain_block const& record, chain_block_id const& id, Record const& rec) {
		auto enc_key = find_record_key(rec, record);
		bool learned = false;
		if(!enc_key) {
			// a user change carries its keys in a KEM envelope we can open regardless of
			// the AES key; extract them so the initial record and any later key rotation
			// become readable (plan 4.6)
			if constexpr(std::is_same_v<Record, user_change_record>) {
				learned = extract_encryption_key(record);
				enc_key = find_record_key(rec, record);
			}
		}
		if(enc_key) {
			verify_block(*enc_key, record, id, rec);
		} else {
			LINFO("No valid key for record [block id = {}, tag = {}, key id = {}]", id, to_hex(record.tag()), rec.encryption_key());
			// store for later, when we hopefully have the key
			records.create(record, record_state::pending_sync);
		}
		if(learned) {
			// a record that arrived before its key waits in pending_sync; a freshly
			// learned key may now unlock it (plan 4.6, out of order key arrival)
			retry_undecrypted_pending();
		}
	}

	/// re-attempt pending_sync records that could not be decrypted for a missing key;
	/// a now readable record is verified and promoted through the normal chain check
	void retry_undecrypted_pending() {
		bool progress = true;
		while(progress) {
			progress = false;
			for(auto const& h : records.find_range(sequence_number{1},
				sequence_number{std::numeric_limits<std::uint64_t>::max()}, record_state::pending_sync)) {
				auto block = h->record();
				progress |= block.deserialise_record<bool>([&](auto const& r) {
						auto key = find_record_key(r, block);
						if(!key) {
							return false;
						}
						record_verifier<std::decay_t<decltype(r)>> ver(*key, r, block.auth());
						if(!ver.is_authentic()) {
							return false;
						}
						if constexpr(std::is_same_v<std::decay_t<decltype(r)>, user_change_record>) {
							extract_encryption_key(block);
						}
						if(check_chain_block(block, h->block_id()) == record_state::in_sync) {
							h->set_state(record_state::in_sync);
							notify_on_record(h);
							return true;
						}
						return false;
					});
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
				// a new record may be what a rejected pending was missing (e.g. the special
				// record it has to reference): let the rejected ones try again
				clear_rejections();
				if(auto own = find_pending_by_op(record)) {
					adopt_committed(own, record, id);
				} else {
					record.deserialise_record([&](auto const& rec) {
							this->handle_block(record, id, rec);
						});
				}
			} else if(handle->state() == record_state::pending_commit) {
				// the server's copy of a record we hold as pending: a lost commit response
				// or a replica resync (plan 4.5) - confirm it under the server's cursor
				update_record_commit_state(handle, record, id);
				rejected_pending.erase(record.tag());
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

	/**
	 * Switch to another replica of the storage (plan 4.5, weak modes): every confirmed
	 * record is demoted to pending_commit (op id and content survive), the partial
	 * records of the old replica are dropped and the chain is refetched from the start.
	 * The new replica's copies re-confirm the records under its cursor (the pending
	 * adoption in handle_incoming_record); records only we hold are committed to it.
	 */
	void begin_replica_resync(crypto::public_key_id const& owner) {
		LINFO("resyncing with a different replica [owner = {}]", owner);
		auto const all = sequence_number{std::numeric_limits<std::uint64_t>::max()};
		for(auto const& h : records.find_range(sequence_number{1}, all, record_state::in_sync)) {
			h->set_state(record_state::pending_commit);
		}
		for(auto const& h : records.find_range(sequence_number{1}, all, record_state::acked)) {
			h->set_state(record_state::pending_commit);
		}
		// only the pending_sync partials are left with server sequences; drop them
		records.truncate_from(sequence_number{1});
		records.set_cursor_owner(owner.data());
		server_seq = sequence_number{};
	}

	/// replica switch detection (plan 4.5); no-op for servers without an identity
	void check_cursor_owner(crypto::public_key_id const& server_id) {
		if(server_id.is_valid()) {
			auto owner = records.cursor_owner();
			if(owner.empty()) {
				records.set_cursor_owner(server_id.data());
			} else if(owner != server_id.data()) {
				if(config.mode == sync_mode::require_all_seen) {
					// strict mode pins the client to one chain; switching needs phase 6
					LWARN("connected to a different replica in strict mode [owner = {}]", server_id);
				} else {
					begin_replica_resync(server_id);
				}
			}
		}
	}

	/// tag of the newest in sync special record; goes into every created record base (plan 4.3)
	record_tag last_special_tag() const {
		record_tag tag;
		auto seq = records.last_special_sequence();
		if(seq.is_valid()) {
			if(auto h = records.find(seq)) {
				tag = h->tag();
			}
		}
		return tag;
	}

	auth_record<data_change_record> update_record(encryption_key const& key, data_change_record_verifier& ver) const {
		auto last_block = records.last_block();
		LINFO("updating last block to {}", last_block);

		std::optional<crypto::private_key> signer;
		if(config.auth_mode == auth_mode::sign_records) {
			signer = my_private_key(crypto.private_data());
		}

		data_change_record_creator creator(key, last_block, signer, ver.base().op_id(), last_special_tag());
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

		user_change_record_creator creator(key, last_block, signer, ver.base().op_id(), last_special_tag());
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

		segment_record_creator creator(key, last_block, signer, ver.base().op_id(), last_special_tag());
		// the covered range moved underneath the segment: recompute the end and the tag
		// list from the storage, keeping the caller's header (metadata, creation time)
		creator.set_data(ver.header(), make_segment_data(last_block));
		return creator.result();
	}

	chain_block update_pending_commit(chain_block const& record) {
		return record.deserialise_record<chain_block>([&](auto const& rec) {
				//check if we are already trying to commit pending record, so that we don't overwrite it while in progress
				if(rec.last_seen_block() == records.last_block() && rec.last_seen_special_tag() == last_special_tag()) {
					// already up-to-date it seems
					return chain_block{};
				}

				// colliding key sequences (D9): the key that authenticates the record
				auto enc_key = find_record_key(rec, record);
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
				state.special_ref = rec.last_seen_special_tag();
				state.newest_special = last_special_tag();
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

	/**
	 * Rebuild the pending record on the current head when the rules or an object
	 * conflict require it. A record that cannot be rebuilt (its key is unknown, it does
	 * not authenticate) is set invalid and reported false: the event loop swallows
	 * exceptions, so throwing here would silently stall every later commit.
	 */
	bool rebase_if_needed(record_handle const& handle, std::deque<record_handle> const& conflicts) {
		bool usable = true;
		if(!conflicts.empty() || pending_needs_rebase(handle->record())) {
			try {
				auto record = update_pending_commit(handle->record());
				if(record.is_valid()) {
					handle->set_record(record);
				}
				notify_conflicts(handle, conflicts);
			} catch(error const& err) {
				LWARN("dropping pending record that cannot be rebuilt [tag = {}, err = {}]", to_hex(handle->tag()), err);
				handle->set_state(record_state::invalid);
				usable = false;
			}
		}
		return usable;
	}

	void try_commit_pending() {
		if(!pushing_pending_commit && !fork_suspected) {
			//t: can we optimise when we are trying to push commits again
			// ie. pushing currently even if we just did and something came in meanwhile
			LTRACE("trying to commit pending records");
			auto handle = records.find_first_pending_commit();
			bool committed = false;
			while(handle && !committed) {
				auto conflicts = find_oid_conflicts(handle->record());
				if(!conflicts.empty() && config.conflicts == conflict_policy::ask) {
					cancel_conflicting(handle, conflicts);
					// the cancelled record is invalid now, move on to the next pending one
					handle = records.find_first_pending_commit();
				} else if(!rebase_if_needed(handle, conflicts)) {
					// unusable (no key, not authentic): dropped, on to the next pending one
					handle = records.find_first_pending_commit();
				} else {
					if(is_rejected_unchanged(handle)) {
						// the rebase changed nothing since the server rejected it: leave it
						// until new records, a completed fetch or a reconnect
						handle = records.find_next_pending_commit(handle);
					} else {
						commit_record(handle);
						committed = true;
					}
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
	/// the storage's validity limits (RDS 8), persisted in the record storage; 0 = unknown
	storage_limits limits;
	/// the tags of the commit requests without an answer yet, by request handle
	std::map<request_handle, record_tag> in_flight_commits;
	/// a pending record the server rejected, in the form (hash) it was rejected in
	struct rejection {
		octet_vector hash;
		bool duplicate{};
	};
	/// pending records the server rejected; try_commit_pending skips them while they are
	/// unchanged, new records / a completed fetch / a reconnect clear the marks
	std::map<record_tag, rejection> rejected_pending;
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
	impl_->clear_rejections();
	auto handle = impl_->comm.fetch_sequence_number();
	LTRACE("on_connected, requested sequence number (request handle {})", handle);
}

void sync_engine::on_disconnected(std::optional<error> err) {
	std::unique_lock lock{impl_->mutex};
	impl_->pushing_pending_commit = 0;
	// the answers to these never come
	impl_->in_flight_commits.clear();
	LTRACE("on_disconnected [error = {}]", err.value_or(error()));
	// nothing for sync_engine
}

void sync_engine::on_sequence_number_response(request_handle req_handle, result<sequence_info> const& res) {
	std::unique_lock lock{impl_->mutex};
	if(res) {
		LINFO("on_sequence_number_response: {} (request handle {})", res.value().sequence, req_handle);
		impl_->check_cursor_owner(res.value().server_id);
		impl_->update_server_seq(res.value().sequence);
		impl_->learn_limits(res.value().limits);
		if(!impl_->fetch_missing("behind the server")) {
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
			} else {
				impl_->on_fetch_complete();
			}
		} else {
			impl_->on_fetch_complete();
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
	auto const committed_tag = impl_->take_in_flight(req_handle);

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

		impl_->update_server_seq(res.server_max_sequence);
		if(check_result_error(res.data, protocol::errc::record_out_of_sync)) {
			impl_->on_out_of_sync_rejected(committed_tag);
		} else if(check_result_error(res.data, protocol::errc::record_already_committed)) {
			impl_->on_duplicate_rejected(committed_tag);
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
	data_change_record_creator creator(impl_->crypto.enc_keys().current_key(), last_block, signer
		, {}, impl_->last_special_tag());
	creator.add_change(std::move(oid), last_oid_tag, std::move(mdata));

	auto record = creator.result();
	impl_->check_record_size(record);
	record_handle h = impl_->records.create(record);
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
	user_change_record_creator creator(impl_->crypto.enc_keys().current_key(), last_block, signer
		, {}, impl_->last_special_tag());
	creator.set_change(std::move(change_data), std::move(mdata));

	auto record = creator.result();
	impl_->check_record_size(record);
	record_handle h = impl_->records.create(record);
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
	segment_record_creator creator(impl_->crypto.enc_keys().current_key(), last_block, signer
		, {}, impl_->last_special_tag());
	creator.set_change(impl_->make_segment_data(last_block), std::move(mdata));

	auto record = creator.result();
	impl_->check_record_size(record);
	record_handle h = impl_->records.create(record);
	impl_->commit_record(h);

	return h;
}

octet_vector sync_engine::prune_history(record_tag const& segment_tag) {
	std::unique_lock lock{impl_->mutex};
	LTRACE("prune history");

	record_handle segment = segment_tag.empty()
		? impl_->records.find_last_of_type(segment_record_tag)
		: impl_->records.find_tag(segment_tag);
	bool const valid = segment && segment->type() == segment_record_tag
		&& segment->state() == record_state::in_sync;
	if(!valid) {
		throw error(errc::constraint_violation, "local prune requires a committed segment as the anchor");
	}

	auto const anchor = segment->block_id();
	auto retained = impl_->records.object_chain_tags_below(anchor.sequence);
	auto removed = impl_->records.truncate_prefix(anchor.sequence, retained);
	LINFO("pruned local history [anchor=({},{}), removed={}, retained={}]"
		, anchor.sequence, to_hex(anchor.hash), removed.size(), retained.size());

	// verification anchors here from now on; later sessions get the hash from the config
	impl_->config.trusted_anchor = anchor.hash;
	return anchor.hash;
}

util::result<history_verify_report> sync_engine::verify_history() const {
	std::unique_lock lock{impl_->mutex};
	LTRACE("verify history");
	return sync::verify_history(impl_->records, impl_->crypto.enc_keys(), impl_->config.verification
		, impl_->config.trusted_anchor);
}

}
