// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/util/octet_vector.hpp>

#include <spsync/util/content_auth.hpp>

namespace securepath::sync::util {

TEST_CASE("content_auth", "[unit]") {
	crypto::public_key_cache keys;

	octet_vector tag = to_octet_vector("tes test tes");
	octet_vector record = to_octet_vector("the serialised record bytes");
	content_auth auth{tag};
	CHECK(auth.tag() == tag);
	CHECK(!auth.has_signature());
	CHECK(!auth.signature_issuer());
	CHECK(test::check_serialisation(auth));

	CHECK(auth.verify(keys, record).code() == make_error_code(errc::invalid_state));

	auto key = crypto::generate_private_key();
	auth.sign(key, record);

	CHECK(auth.has_signature());
	CHECK(test::check_serialisation(auth));

	CHECK(auth.verify(keys, record).code() == make_error_code(crypto::errc::no_such_key));
	keys.insert(key.public_key());

	CHECK(!auth.verify(keys, record));
	REQUIRE(auth.signature_issuer());
	CHECK(*auth.signature_issuer() == key.id());

	// the signature covers the record bytes: different bytes must not verify
	octet_vector other = to_octet_vector("some other record bytes");
	CHECK(auth.verify(keys, other).code() == make_error_code(crypto::errc::signature_not_authentic));
}

}
