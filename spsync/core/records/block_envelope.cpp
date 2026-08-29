#include "block_envelope.hpp"

#include <securepath/crypto/hash.hpp>
#include <securepath/log/log.hpp>

#include <string_view>

namespace securepath::sync {
namespace {

void append_u32(octet_vector& buf, std::uint32_t v) {
	for(int i = 3; i >= 0; --i) {
		buf.push_back(std::uint8_t(v >> (i*8)));
	}
}

void append_u64(octet_vector& buf, std::uint64_t v) {
	for(int i = 7; i >= 0; --i) {
		buf.push_back(std::uint8_t(v >> (i*8)));
	}
}

void append_sized(octet_vector& buf, octet_vector const& v) {
	append_u32(buf, std::uint32_t(v.size()));
	buf.insert(buf.end(), v.begin(), v.end());
}

}

octet_vector block_envelope::assignment_digest(octet_vector const& storage_id) const {
	std::string_view const context{"spsync-assign"};
	octet_vector buf;
	buf.insert(buf.end(), context.begin(), context.end());
	append_sized(buf, storage_id);
	append_sized(buf, origin_.data());
	append_u64(buf, term_);
	append_u64(buf, block_.sequence().value);
	append_sized(buf, block_.hash());
	return crypto::hash(buf);
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
