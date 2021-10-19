#ifndef SPSYNC_UTIL_CONTENT_AUTH_HEADER
#define SPSYNC_UTIL_CONTENT_AUTH_HEADER

#include <securepath/crypto/error.hpp>
#include <securepath/crypto/signature.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/public_key_access.hpp>

#include <securepath/serialisation/types.hpp>

namespace securepath::sync::util {

/** content authenticity, contains for example signature to make sure a piece of data is authentic
 * This has always AES GCM tag and optional asymmetric cryptography signature over this tag
 */
class content_auth {
public:
	explicit content_auth(octet_vector tag = {});

	/// Returns the AES GCM tag that protects the content
	octet_vector tag() const;

	/// Sign the tag
	void sign(crypto::private_key const& key);

	/// check if the signature is present
	bool has_signature() const;

	std::optional<crypto::public_key_id> signature_issuer() const;

	/// verify the signature
	error verify(crypto::public_key_access const&) const;

	bool operator==(content_auth const& auth) const;
	bool operator!=(content_auth const& auth) const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & gcm_tag_ & signature_ & trailing_data_;
	}
private:
	//AES GCM tag over the record
	octet_vector gcm_tag_;

	//optional signature over the gcm_tag
	std::optional<crypto::signature> signature_;

	serialisation::trailing_data trailing_data_;
};

}

#endif