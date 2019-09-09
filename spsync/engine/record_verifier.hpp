#ifndef SPSYNC_ENGINE_RECORD_VERIFIER_HEADER
#define SPSYNC_ENGINE_RECORD_VERIFIER_HEADER

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/user_change_record.hpp>
#include <spsync/core/records/segment_record.hpp>
#include <spsync/core/records/record.hpp>
#include <spsync/util/content_auth.hpp>
#include <securepath/crypto/auth_stream_cipher.hpp>

namespace securepath::sync {

/**
 * Base class for the record verifier helpers
 */
class record_verifier_base {
public:

	record_verifier_base(encryption_key const& key, util::content_auth auth, record_base record);

	template<typename Record>
	record_verifier_base(encryption_key const& key, auth_record<Record> const& rec)
	: record_verifier_base(key, rec.auth, rec.record)
	{}

	/// Return whether the record is authentic based on the auth stream tag. This can be called only once as it consumes the tag.
	bool is_authentic() const;

protected:
	util::content_auth auth_;
	record_base base_;
	crypto::auth_stream_cipher_ptr decryptor_;
};

/**
 * Helper class to verify data change record authenticity and extract the decrypted parts
 */
class data_change_record_verifier : public record_verifier_base {
public:
	/// contains the data for single entry
	struct single_data {
		plain_single_change_data data;
		data_change_header header;
	};

	/// Construct to verify authenticity and extract the decrypted data.
	data_change_record_verifier(encryption_key const& key, auth_record<data_change_record> const& record);

	/// Returns the decrypted and extracted data
	std::deque<single_data> headers() const { return headers_; }
private:
	std::deque<single_data> headers_;
};

/**
 * Helper class to verify user change record authenticity and extract the decrypted part
 */
class user_change_record_verifier : public record_verifier_base {
public:
	/// Construct to verify authenticity and extract the decrypted data.
	user_change_record_verifier(encryption_key const& key, auth_record<user_change_record> const& record);

	/// Returns the decrypted header from the record
	user_change_header header() const;
private:
	std::optional<user_change_header> header_;
};


}

#endif
