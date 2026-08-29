#pragma once

#include <spsync/core/sync_mode.hpp>
#include <spsync/core/record_storage.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/util/result.hpp>

#include <securepath/crypto/public_key_id.hpp>
#include <securepath/database/connection.hpp>

#include <memory>
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
};

/**
 * Server side block chain handler.
 *
 * The mode enforcement cursors are derived from the record storage by replay on construction,
 * so enforcement survives restarts. validate() and apply() are separated so that a replication
 * layer can validate on the leader and apply deterministically on every replica.
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

	/// check whether the block could be committed in the current state, without changing anything
	error validate(chain_block const&) const;

	/**
	 * Append the block to the chain. The caller is expected to have validated the block;
	 * apply only classifies it (for the mode cursors) and saves it.
	 */
	chain_block apply(chain_block const&);

	/// try to commit chain block (validate + apply)
	util::result<chain_block> commit_block(chain_block const&);

	record_storage& records() { return records_; }
	record_storage const& records() const { return records_; }

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

	error verify_signature(chain_block const& block, std::optional<crypto::public_key_id>& signer) const;
	chain_block set_and_save_block(chain_block block, rec_type type);
	rule_result check_rules(data_change_record const& rec) const;
	rule_result check_rules(user_change_record const& rec) const;
	rule_result check_rules(segment_record const& rec) const;
	error check_rules_add(data_change_record const& rec) const;
	error check_rules_existing(data_change_record const& rec) const;
	error check_rules_special_seen(chain_block_id const& last_seen_block) const;
private:
	chain_sync_config config_;
	crypto::public_key_access* keys_{};
	record_storage records_;
	chain_block_id last_block_;

	// enforcement cursors, replayed from the storage on construction and advanced on apply
	sequence_number last_data_add_remove_;
	sequence_number last_user_change_or_segment_;
};

}

