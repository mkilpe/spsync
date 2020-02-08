#ifndef SPSYNC_ENGINE_RECORD_CREATOR_HEADER
#define SPSYNC_ENGINE_RECORD_CREATOR_HEADER

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
	/// construct to create the record_base which is common to all records and initialise encryption+authentication
	record_creator_base(encryption_key const& key, chain_block_id last_seen);

	/// Returns authentication tag for the record, this can be called only once after constructing the record has been done
	util::content_auth authentication_tag();

protected:
	record_base base_;
	crypto::auth_stream_cipher_ptr encryptor_;
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
	void set_change(users access, metadata);

	//todo: add the data to user_change_info, like possible old encryption keys, new encryption key

	/// Returns the ready user_change_record, it can be called only once as it will move content
	auth_record<user_change_record> result();

private:
	plain_user_change_data plain_record_;
	metadata meta_;
	user_change_info info_;
};

/**
 * Helper class to create segment records
 */
class segment_record_creator: public record_creator_base {
public:
	using record_creator_base::record_creator_base;

	/// Returns the ready segment_record, it can be called only once as it will move content
	auth_record<segment_record> result();
};

}

#endif
