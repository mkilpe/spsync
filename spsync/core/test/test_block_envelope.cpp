#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/records/block_envelope.hpp>
#include <spsync/test/test_block_creator.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>

namespace securepath::sync {

TEST_CASE("block_envelope sign and verify", "[unit]") {
	crypto::public_key_cache keys;
	auto key = crypto::generate_private_key();
	octet_vector storage_id = securepath::test::random_octet_vector(16);

	test::test_block_creator creator;
	auto block = creator.test_user_change();

	block_envelope env{block, key.id()};
	CHECK(!env.is_signed());
	CHECK(env.verify(storage_id, keys).code() == make_error_code(securepath::errc::invalid_state));

	env.sign(storage_id, key);
	CHECK(env.is_signed());
	CHECK(env.origin() == key.id());

	CHECK(env.verify(storage_id, keys).code() == make_error_code(crypto::errc::no_such_key));
	keys.insert(key.public_key());
	CHECK(!env.verify(storage_id, keys));

	// the assignment is bound to the storage id
	octet_vector other_storage = securepath::test::random_octet_vector(16);
	CHECK(env.verify(other_storage, keys).code() == make_error_code(crypto::errc::signature_not_authentic));

	// round-trip keeps it verifiable
	auto bytes = serialisation::asn_der_serialise(env);
	auto back = serialisation::asn_der_deserialise<block_envelope>(bytes);
	CHECK(back.origin() == key.id());
	CHECK(back.term() == 0);
	CHECK(!back.verify(storage_id, keys));

	// the signature binds the term as well
	block_envelope env2{block, key.id(), 1};
	env2.sign(storage_id, key);
	CHECK(env2.term() == 1);
	CHECK(!env2.verify(storage_id, keys));
}

}
