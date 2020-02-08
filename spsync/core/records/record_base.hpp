#ifndef SPSYNC_CORE_RECORD_BASE_HEADER
#define SPSYNC_CORE_RECORD_BASE_HEADER

#include <spsync/core/chain_block_id.hpp>
#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * The common parts in records.
 */
class record_base {
public:

	record_base() = default;
	record_base(chain_block_id last_seen_block, octet_vector iv, sequence_number enc_key_id)
	: last_seen_block_(std::move(last_seen_block))
	, iv_(std::move(iv))
	, encryption_key_id_(std::move(enc_key_id))
	{}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & structure_version_ & last_seen_block_
			& iv_ & encryption_key_id_ & trailing_data_;
	}

	/// Returns the sequence number that was the last one seen before this record was created
	chain_block_id last_seen_block() const { return last_seen_block_; }

	/// Returns the initialisation vector that is used to encrypted the data in this record
	octet_vector const& iv() const { return iv_; }

	/// Returns the sequence number of the encryption key used for this record
	sequence_number encryption_key() const { return encryption_key_id_; }

private:
	// version of the current structure
	int structure_version_{1};

	// this is the last chain block id the client has seen when creating this record
	chain_block_id last_seen_block_;

	// initialisation vector for encrypting the record header
	octet_vector iv_;

	// the sequence number for the key used to encrypt this record
	sequence_number encryption_key_id_;

	serialisation::trailing_data trailing_data_;
};

}

#endif
