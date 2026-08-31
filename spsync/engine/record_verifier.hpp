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
 * Base class for the record verifier helpers
 */
class record_verifier_base {
public:
	record_verifier_base(encryption_key const& key, util::content_auth auth, record_base record);

	/// Return whether the record is authentic based on the auth stream tag. This can be called only once as it consumes the tag.
	bool is_authentic() const;

	/// The record base for the verified record
	record_base const& base() const { return base_; }

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
	data_change_record_verifier(encryption_key const& key, data_change_record const& record, util::content_auth auth);

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
	user_change_record_verifier(encryption_key const& key, user_change_record const& record, util::content_auth auth);

	/// Returns the decrypted header from the record
	user_change_header header() const;

	/// Returns the plain user change data from the record
	plain_user_change_data data() const;
private:
	std::optional<user_change_header> header_;
	plain_user_change_data data_;
};

/**
 * Helper class to verify segment record authenticity and extract the decrypted part
 */
class segment_record_verifier : public record_verifier_base {
public:
	/// Construct to verify authenticity and extract the decrypted data.
	segment_record_verifier(encryption_key const& key, segment_record const& record, util::content_auth auth);

	/// Returns the decrypted header from the record
	segment_header header() const;

	/// Returns the plain segment data from the record
	plain_segment_data const& data() const;
private:
	std::optional<segment_header> header_;
	plain_segment_data data_;
};


template<typename> struct record_verifier;
template<> struct record_verifier<data_change_record> : data_change_record_verifier {
	using data_change_record_verifier::data_change_record_verifier;
};
template<> struct record_verifier<user_change_record> : user_change_record_verifier {
	using user_change_record_verifier::user_change_record_verifier;
};
template<> struct record_verifier<segment_record> : segment_record_verifier {
	using segment_record_verifier::segment_record_verifier;
};

}

