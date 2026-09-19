#include "block_envelope.hpp"

#include <spsync/util/digest_buffer.hpp>

#include <securepath/crypto/hash.hpp>
#include <securepath/log/log.hpp>

namespace securepath::sync {

octet_vector block_envelope::assignment_digest(octet_vector const& storage_id) const {
	util::digest_buffer buf{"spsync-assign"};
	buf.sized(storage_id).sized(origin_.data()).u64(term_).u64(block_.sequence().value).sized(block_.hash());
	return crypto::hash(buf.octets());
}

void block_envelope::sign(octet_vector const& storage_id, crypto::private_key const& key) {
	origin_ = key.id();
	signature_ = key.sign(assignment_digest(storage_id));
}

error block_envelope::verify(octet_vector const& storage_id, crypto::public_key_access const& keys) const {
	if(!signature_.is_valid()) {
		return make_error(securepath::errc::invalid_state, "block envelope is not signed");
	}
	if(signature_.issuer() != origin_) {
		LOG_WARN("block envelope signer differs from the stated origin [origin={}, signer={}]", origin_, signature_.issuer());
		return make_error(crypto::errc::signature_not_authentic, "envelope signer differs from origin");
	}
	auto pkey = keys.find(origin_);
	if(!pkey) {
		return make_error(crypto::errc::no_such_key);
	}
	if(!pkey->verify(signature_, assignment_digest(storage_id))) {
		LOG_WARN("block envelope assignment signature is not authentic [origin={}]", origin_);
		return make_error(crypto::errc::signature_not_authentic);
	}
	return {};
}

}
