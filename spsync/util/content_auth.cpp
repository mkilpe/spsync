#include "content_auth.hpp"

#include <securepath/crypto/hash.hpp>
#include <securepath/log/log.hpp>

#include <string_view>

namespace securepath::sync::util {

content_auth::content_auth(octet_vector tag)
: gcm_tag_(std::move(tag))
{}

octet_vector content_auth::tag() const {
	return gcm_tag_;
}

namespace {

std::uint32_t const current_digest_version{1};

octet_vector signing_digest(octet_span record_bytes, octet_vector const& tag) {
	std::string_view const context{"spsync-record"};
	octet_vector buf;
	buf.reserve(context.size() + record_bytes.size() + tag.size());
	buf.insert(buf.end(), context.begin(), context.end());
	buf.insert(buf.end(), record_bytes.begin(), record_bytes.end());
	buf.insert(buf.end(), tag.begin(), tag.end());
	return crypto::hash(buf);
}

}

void content_auth::sign(crypto::private_key const& key, octet_span record_bytes) {
	digest_version_ = current_digest_version;
	signature_ = key.sign(signing_digest(record_bytes, gcm_tag_));
}

bool content_auth::has_signature() const {
	return static_cast<bool>(signature_);
}

std::optional<crypto::public_key_id> content_auth::signature_issuer() const {
	return signature_ ? signature_->issuer() : std::optional<crypto::public_key_id>();
}

error content_auth::verify(crypto::public_key_access const& keys, octet_span record_bytes) const {
	error err;
	if(signature_) {
		if(digest_version_ != current_digest_version) {
			LOG_WARN("unknown content auth digest version: {}", digest_version_);
			return make_error(errc::invalid_state, "unknown content auth digest version");
		}
		auto pkey = keys.find(signature_->issuer());
		if(pkey) {
			if(!pkey->verify(*signature_, signing_digest(record_bytes, gcm_tag_))) {
				LOG_WARN("content auth tag is not authentic [kid={}]", signature_->issuer());
				err = make_error(crypto::errc::signature_not_authentic);
			}
		} else {
			LOG_WARN("could not verify content_auth tag because we do not have the public key [kid={}]", signature_->issuer());
			err = make_error(crypto::errc::no_such_key);
		}
	} else {
		LOG_WARN("could not verify authenticity because there is no signature");
		err = make_error(errc::invalid_state, "could not verify authenticity because there is no signature");
	}
	return err;
}

bool content_auth::operator==(content_auth const& auth) const {
	return gcm_tag_ == auth.gcm_tag_ &&
		digest_version_ == auth.digest_version_ &&
		bool(signature_) == bool(auth.signature_) &&
		(!signature_ || *signature_ == *auth.signature_) &&
		trailing_data_ == auth.trailing_data_;
}

}
