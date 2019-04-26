#ifndef SPSYNC_UTIL_CONTENT_AUTH_HEADER
#define SPSYNC_UTIL_CONTENT_AUTH_HEADER

#include <securepath/crypto/signature.hpp>
#include <securepath/serialisation/types.hpp>

namespace securepath::sync::util {

/** content authenticity, contains for example signature to make sure a piece of data is authentic
 * This can has always AES GCM tag and optional asymmetric cryptography signature over this tag
 */
class content_auth {
public:
	content_auth(octet_vector tag)
	: gcm_tag_(std::move(tag))
	{}

	/// Returns the AES GCM tag that protects the content
	octet_vector tag() const { return gcm_tag_; }

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