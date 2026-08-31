#pragma once

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>
#include <spsync/core/records/chain_block.hpp>
#include <spsync/util/content_auth.hpp>
#include <securepath/crypto/auth_stream_cipher.hpp>

namespace securepath::sync {

/**
 * Base class for the record creator helpers
 */
class record_creator_base {
public:
	/**
	 * Construct to create the record_base which is common to all records and initialise
	 * encryption+authentication. op_id: the stable operation id; empty generates a new
	 * one, a rebase passes the original (the base is authenticated at construction, so
	 * the op id cannot change afterwards).
	 */
	record_creator_base(encryption_key const& key, chain_block_id last_seen, std::optional<crypto::private_key> = std::nullopt, octet_vector op_id = {});

	/// Returns authentication tag for the record, this can be called only once after constructing the record has been done
	util::content_auth authentication_tag();

	/// sign auth over the serialised record when a signer was given
	template<typename Record>
	util::content_auth make_auth(Record const& record) {
		auto auth = authentication_tag();
		if(signer_) {
			auth.sign(*signer_, serialisation::asn_der_serialise_choice<record_types>(record));
		}
		return auth;
	}

protected:
	record_base base_;
	crypto::auth_stream_cipher_ptr encryptor_;
	std::optional<crypto::private_key> signer_;
};

/**
 * Helper class to create data change records
 */
class data_change_record_creator: public record_creator_base {
public:
	using record_creator_base::record_creator_base;

	//todo: support change data
	/// add single change to the data change record
	void add_change(object_id oid, record_tag previous_oid_record_tag, metadata);

	/// Returns the ready data_change_record, it can be called only once as it will move content
	auth_record<data_change_record> result();

	/// Add the data structures (e.g. from verifier)
	void add_change(data_change_header, plain_single_change_data);
private:
	std::deque<single_change> changes_;
};

/**
 * Helper class to create user change records
 */
class user_change_record_creator: public record_creator_base {
public:
	using record_creator_base::record_creator_base;

	/// set the user access data with the metadata
	void set_change(plain_user_change_data access, metadata);

	/// Returns the ready user_change_record, it can be called only once as it will move content
	auth_record<user_change_record> result();

	/// Set the data in one go (e.g. from verifier)
	void set_data(user_change_header, plain_user_change_data);
private:
	plain_user_change_data plain_record_;
	user_change_header header_;
};

/**
 * Helper class to create segment records
 */
class segment_record_creator: public record_creator_base {
public:
	using record_creator_base::record_creator_base;

	/// set the plain segment data with the metadata (goes to the encrypted header)
	void set_change(plain_segment_data data, metadata);

	/// Returns the ready segment_record, it can be called only once as it will move content
	auth_record<segment_record> result();

	/// Set the data in one go (e.g. from verifier)
	void set_data(segment_header, plain_segment_data);
private:
	plain_segment_data plain_record_;
	segment_header header_;
};

}

