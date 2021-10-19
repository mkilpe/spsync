#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/rsa.hpp>
#include <securepath/util/octet_vector.hpp>

#include <spsync/util/content_auth.hpp>

namespace securepath::sync::util {

TEST_CASE("content_auth", "[unit]") {
	crypto::public_key_cache keys;

	octet_vector tag = to_octet_vector("tes test tes");
	content_auth auth{tag};
	CHECK(auth.tag() == tag);
	CHECK(!auth.has_signature());
	CHECK(!auth.signature_issuer());
	CHECK(test::check_serialisation(auth));

	CHECK(auth.verify(keys).code() == make_error_code(errc::invalid_state));

	auto key = crypto::generate_rsa_private_key(1024);
	auth.sign(key);

	CHECK(auth.has_signature());
	CHECK(test::check_serialisation(auth));

	CHECK(auth.verify(keys).code() == make_error_code(crypto::errc::no_such_key));
	keys.insert(key.public_key());

	CHECK(!auth.verify(keys));
	REQUIRE(auth.signature_issuer());
	CHECK(*auth.signature_issuer() == key.id());
}

}
