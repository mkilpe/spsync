#pragma once

#include <spsync/core/chain_block_id.hpp>
#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * The common parts in records.
 */
class record_base {
public:

	record_base() = default;
	record_base(chain_block_id last_seen_block, octet_vector iv, sequence_number enc_key_id, octet_vector op_id = {},
		record_tag last_seen_special_tag = {})
	: last_seen_block_(std::move(last_seen_block))
	, iv_(std::move(iv))
	, encryption_key_id_(std::move(enc_key_id))
	, op_id_(std::move(op_id))
	, last_seen_special_tag_(std::move(last_seen_special_tag))
	{}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & structure_version_ & last_seen_block_
			& iv_ & encryption_key_id_ & op_id_ & last_seen_special_tag_ & trailing_data_;
	}

	/// Returns the chain block id that was the last one seen before this record was created
	chain_block_id const& last_seen_block() const { return last_seen_block_; }

	/// Returns the initialisation vector that is used to encrypted the data in this record
	octet_vector const& iv() const { return iv_; }

	/// Returns the sequence number of the encryption key used for this record
	sequence_number encryption_key() const { return encryption_key_id_; }

	/**
	 * The stable operation id (plan 2.2/D6): chosen by the creating client, preserved
	 * across rebases and inside the authenticated base, so the same operation can be
	 * deduplicated even after the record was rebuilt with a new tag.
	 */
	octet_vector const& op_id() const { return op_id_; }

	/// re-set the op id (only before the base is authenticated, i.e. at creation)
	void set_op_id(octet_vector id) { op_id_ = std::move(id); }

	/**
	 * Tag of the newest special record (user change or segment) the creating client had
	 * seen (plan 4.3/D4). Tag bound so the weak-mode seen rules work across replicas
	 * whose local sequences differ; empty when no special record was seen. Authenticated
	 * with the base.
	 */
	record_tag const& last_seen_special_tag() const { return last_seen_special_tag_; }

public:
	/// Re-set the last seen block
	void set_last_seen_block(chain_block_id id) { last_seen_block_ = std::move(id); }

private:
	// version of the current structure
	int structure_version_{1};

	// this is the last chain block id the client has seen when creating this record
	chain_block_id last_seen_block_;

	// initialisation vector for encrypting the record header
	octet_vector iv_;

	// the sequence number for the key used to encrypt this record
	sequence_number encryption_key_id_;

	// stable operation id, chosen at creation and preserved across rebases
	octet_vector op_id_;

	// tag of the newest special record seen at creation (plan 4.3/D4)
	record_tag last_seen_special_tag_;

	serialisation::trailing_data trailing_data_;
};

}

