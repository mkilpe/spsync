#ifndef SPSYNC_UTIL_CONTENT_AUTH_HEADER
#define SPSYNC_UTIL_CONTENT_AUTH_HEADER

#include <securepath/crypto/error.hpp>
#include <securepath/crypto/signature.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/public_key_access.hpp>

#include <securepath/serialisation/types.hpp>
#include <securepath/util/span.hpp>

namespace securepath::sync::util {

/**
 * content authenticity: always carries the AES GCM tag over the record, plus an optional
 * signature over sha3-512("spsync-record" || serialised record || gcm tag) - the whole
 * record, not just the 128 bit tag (plan 2.1/D5: a group member must not be able to
 * transplant a signature between records sharing a tag).
 */
class content_auth {
public:
	explicit content_auth(octet_vector tag = {});

	/// Returns the AES GCM tag that protects the content
	octet_vector tag() const;

	/// Sign the digest of the serialised record and the tag
	void sign(crypto::private_key const& key, octet_span record_bytes);

	/// check if the signature is present
	bool has_signature() const;

	std::optional<crypto::public_key_id> signature_issuer() const;

	/// verify the signature against the digest of the serialised record and the tag
	error verify(crypto::public_key_access const&, octet_span record_bytes) const;

	bool operator==(content_auth const& auth) const;
	bool operator!=(content_auth const& auth) const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & gcm_tag_ & signature_ & digest_version_ & trailing_data_;
	}
private:
	//AES GCM tag over the record
	octet_vector gcm_tag_;

	//optional signature over the record digest
	std::optional<crypto::signature> signature_;

	//version of the signed digest construction (1 = sha3-512 over context||record||tag)
	std::uint32_t digest_version_{1};

	serialisation::trailing_data trailing_data_;
};

}

#endif