#include "content_auth.hpp"

#include <securepath/log/log.hpp>

namespace securepath::sync::util {

content_auth::content_auth(octet_vector tag)
: gcm_tag_(std::move(tag))
{}

octet_vector content_auth::tag() const {
	return gcm_tag_;
}

void content_auth::sign(crypto::private_key const& key) {
	signature_ = key.sign(gcm_tag_);
}

bool content_auth::has_signature() const {
	return static_cast<bool>(signature_);
}

std::optional<crypto::public_key_id> content_auth::signature_issuer() const {
	return signature_ ? signature_->issuer() : std::optional<crypto::public_key_id>();
}

error content_auth::verify(crypto::public_key_access const& keys) const {
	error err;
	if(signature_) {
		auto pkey = keys.find(signature_->issuer());
		if(pkey) {
			if(!pkey->verify(*signature_, gcm_tag_)) {
				LOG_WARN("content auth tag is not authentic [kid=%]", signature_->issuer());
				err = make_error(crypto::errc::signature_not_authentic);
			}
		} else {
			LOG_WARN("could not verify content_auth tag because we do not have the public key [kid=%]", signature_->issuer());
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
		bool(signature_) == bool(auth.signature_) &&
		(!signature_ || *signature_ == *auth.signature_) &&
		trailing_data_ == auth.trailing_data_;
}

bool content_auth::operator!=(content_auth const& auth) const {
	return !(*this == auth);
}

}
