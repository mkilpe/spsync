#pragma once

#include "chain_log.hpp"

#include <spsync/core/sync_mode.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/util/result.hpp>

#include <securepath/crypto/public_key_id.hpp>
#include <securepath/database/connection.hpp>

#include <optional>

namespace securepath::crypto {
	class public_key_access;
}

namespace securepath::sync {

// t: check and update user access when handling records
// t: check signature

/**
 * Configuration for server side block chain
 */
struct chain_sync_config {
	sync_mode mode{sync_mode::require_all_seen};
	sync::auth_mode	auth_mode{sync::auth_mode::only_tag};
	/// this is id for the repository, it is only used for logging to help trace/debug things if set
	std::string log_id;
	/// maximum records returned for one call
	std::size_t max_returned_records{30};
	/// byte budget of one batch (record content plus a per record allowance): a range of
	/// large records must not wedge (record_data.txt RD10). Kept small so an ordinary
	/// fetch costs a client about this much memory; a batch always holds at least two
	/// records (the first one of a range is the one the client continues from), so big
	/// records (up to max_record_size_range.highest each) still get through - the receivers take
	/// messages up to the transport frame
	std::size_t max_response_bytes{1024 * 1024};
	/// the storage's record content limit (RDS 8); 0 = unlimited. Part of validity: every
	/// replica judges it identically, so it is a creation parameter of the storage
	std::size_t max_record_size{};
	/// how the storage replicates; replicated storages accept only delta mode user
	/// changes (plan 4.6/D9)
	replication_mode replication{replication_mode::none};
};

/**
 * Server side block chain handler.
 *
 * Keeps the validation rules; the storage and the chain head live in chain_log (plan 3.2),
 * which the replication layers talk to directly. The mode enforcement cursors are derived
 * from the record storage by replay on construction, so enforcement survives restarts.
 * validate() and apply() are separated so that a replication layer can validate on the
 * leader and apply deterministically on every replica.
 */
class chain_sync {
public:
	/**
	 * keys: the public keys the server knows, used to verify record signatures when the
	 * auth mode is sign_records (plan 2.3/B7); without it only the structural presence
	 * of a signature is enforced (unit test setups).
	 */
	chain_sync(database::connection_ptr, chain_sync_config config = {}, crypto::public_key_access* keys = nullptr);

	/// returns the latest sequence number
	sequence_number current_sequence_number() const;

	/// get the records [start, end], returns only maximum of config.max_returned_records at once
	std::deque<chain_block> get_records(sequence_number start, sequence_number end) const;

	/// get the envelopes [start, end] for the s2s pull (plan 4.1), capped like get_records
	std::deque<block_envelope> get_envelopes(sequence_number start, sequence_number end) const;

	/// get one origin's envelopes with origin sequence in [from, to], same cap (plan 4.4)
	std::deque<block_envelope> get_envelopes_by_origin(crypto::public_key_id const& origin,
		sequence_number from, sequence_number to) const;

	/// check whether the block could be committed in the current state, without changing anything
	[[nodiscard]] error validate(chain_block const&) const;

	/**
	 * Append the block to the chain. The caller is expected to have validated the block;
	 * apply only classifies it (for the mode cursors) and saves it.
	 */
	chain_block apply(chain_block const&);

	/// try to commit chain block (validate + apply)
	util::result<chain_block> commit_block(chain_block const&);

	/**
	 * Commit a block another server already accepted (plan 4.2/4.3): signatures and
	 * duplicates are checked but the seen rules are not re-enforced - the origin
	 * enforced them against its own order and re-checking against ours would make
	 * replicas diverge on concurrent records (D9: the merge is a union).
	 */
	util::result<chain_block> commit_foreign(chain_block const&);

	/// truncate the log from the given sequence and re-derive the mode cursors;
	/// returns the removed blocks (see chain_log::truncate_from)
	std::vector<chain_block> truncate_from(sequence_number first_removed);

	chain_log& log() { return log_; }
	chain_log const& log() const { return log_; }

	record_storage& records() { return log_.records(); }
	record_storage const& records() const { return log_.records(); }

private:
	enum class rec_type { none = 0, data_add_remove, special };
	struct rule_result {
		error err;
		rec_type type{rec_type::none};
		/// the verified signer of the record (set under sign_records); the access rights
		/// hook for phase 7
		std::optional<crypto::public_key_id> signer;
	};

	/// duplicate check + rule evaluation + classification; does not change any state
	rule_result evaluate(chain_block const& block) const;

	/// duplicate + signature check and classification only, for foreign blocks
	rule_result evaluate_foreign(chain_block const& block) const;
	/// the record content exceeds the storage's max_record_size (RDS 8)
	bool too_big(chain_block const&) const;

	error verify_signature(chain_block const& block, std::optional<crypto::public_key_id>& signer) const;
	chain_block set_and_save_block(chain_block block, rec_type type);
	rule_result check_rules(data_change_record const& rec) const;
	rule_result check_rules(user_change_record const& rec) const;
	rule_result check_rules(segment_record const& rec) const;
	error check_rules_add(data_change_record const& rec) const;
	error check_rules_existing(data_change_record const& rec) const;
	error check_rules_special_seen(record_tag const& last_seen_special) const;
	error check_rules_segment(segment_record const& rec) const;
	error check_segment_backbone(segment_record const& rec) const;
private:
	chain_sync_config config_;
	crypto::public_key_access* keys_{};
	chain_log log_;

	// enforcement cursors, replayed from the storage on construction and advanced on apply
	sequence_number last_data_add_remove_;
	sequence_number last_user_change_or_segment_;
};

}

