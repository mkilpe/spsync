#include "data_ticket.hpp"

#include <spsync/util/digest_buffer.hpp>

#include <securepath/crypto/error.hpp>
#include <securepath/crypto/hash.hpp>
#include <securepath/log/log.hpp>

#include <chrono>

namespace securepath::sync {
data_ticket::data_ticket(octet_vector storage_id, data_descriptor descriptor, crypto::public_key_id member
	, data_right right, time_point expiry)
: storage_id_(std::move(storage_id))
, descriptor_(std::move(descriptor))
, member_(std::move(member))
, right_(static_cast<std::uint32_t>(right))
, expiry_(expiry)
{
}

octet_vector data_ticket::digest() const {
	// the expiry travels in seconds: signed as it is read back
	util::digest_buffer buf{"spsync-data-ticket"};
	buf.sized(storage_id_).sized(descriptor_.manifest_digest).u64(descriptor_.enc_size).u32(descriptor_.chunk_size)
		.sized(member_.data()).u32(right_).u64(static_cast<std::uint64_t>(seconds_since_epoch(expiry_)));
	return crypto::hash(buf.octets());
}

void data_ticket::sign(crypto::private_key const& record_server_key) {
	signature_ = record_server_key.sign(digest());
}

error data_ticket::verify(crypto::public_key_access const& keys, time_point now) const {
	if(!signature_.is_valid()) {
		return make_error(securepath::errc::invalid_state, "data ticket is not signed");
	}
	auto const key = keys.find(signature_.issuer());
	if(!key) {
		return make_error(crypto::errc::no_such_key, "unknown data ticket issuer");
	}
	if(!key->verify(signature_, digest())) {
		LOG_WARN("data ticket signature is not authentic [issuer={}]", signature_.issuer());
		return make_error(crypto::errc::signature_not_authentic);
	}
	if(seconds_since_epoch(expiry_) <= seconds_since_epoch(now)) {
		return make_error(securepath::errc::timeout, "data ticket expired");
	}
	return {};
}

}
