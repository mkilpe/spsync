#pragma once

#include "record_base.hpp"
#include "record_types.hpp"
#include "encrypted_record_header.hpp"
#include "user_change_header.hpp"

#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/users.hpp>
#include <securepath/crypto/encrypted_content.hpp>
#include <securepath/crypto/enveloped_content.hpp>

namespace securepath::sync {

struct env_structure {
	std::vector<encryption_key> enc_keys;
	serialisation::trailing_data trailing_data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & enc_keys & trailing_data;
	}
};

class plain_user_change_data {
public:
	plain_user_change_data(users access = {})
	: access_(std::move(access))
	{}

	/// get the user access changes
	users access() const { return access_; }
	crypto::enveloped_content const& enveloped_content() const { return enveloped_change_data_; }

	void set_enveloped_content(crypto::enveloped_content c) { enveloped_change_data_ = std::move(c); }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & access_ & encrypted_change_data_ & enveloped_change_data_ & trailing_data_;
	}
private:
	// the change in users access
	users access_;
	crypto::encrypted_content encrypted_change_data_;
	crypto::enveloped_content enveloped_change_data_;
	serialisation::trailing_data trailing_data_;
};

class user_change_record : public record_base {
public:
	static constexpr record_type_tag tag = user_change_record_tag;

	user_change_record() = default;
	user_change_record(record_base base, plain_user_change_data data, encrypted_record_header<user_change_header> header)
	: record_base(std::move(base))
	, data_(std::move(data))
	, header_(std::move(header))
	{}

	/// Returns the user change data for this record
	plain_user_change_data data() const { return data_; }

	/// Returns the encrypted header
	encrypted_record_header<user_change_header> header() const { return header_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & static_cast<record_base&>(*this) & data_ & header_;
	}
private:
	plain_user_change_data data_;
	encrypted_record_header<user_change_header> header_;
};

}

