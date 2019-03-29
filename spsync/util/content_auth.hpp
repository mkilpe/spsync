#ifndef SPSYNC_UTIL_CONTENT_AUTH_HEADER
#define SPSYNC_UTIL_CONTENT_AUTH_HEADER

#include <securepath/crypto/hash.hpp>
#include <securepath/serialisation/types.hpp>

namespace securepath::sync::util {

/** content authenticity, contains for example signature to make sure a piece of data is authentic
 * This can curretly be either asymmetric cryptography signature or AES GCM tag
 */
class content_auth {
public:


	template<typename Ar>
	void serialise(Ar& ar) {
		serialiation::sequence<Ar> seq(ar);
		seq & trailing_data;
	}
private:
	serialisastion::trailing_data trailing_data
};

}

#endif