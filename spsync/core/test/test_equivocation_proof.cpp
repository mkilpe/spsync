#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/core/records/equivocation_proof.hpp>
#include <spsync/test/test_block_creator.hpp>

#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {
namespace {

/// the origin's signed assignment of a block
block_envelope assigned(chain_block const& block, crypto::private_key const& origin, octet_vector const& sid, std::uint64_t term = 0) {
	block_envelope env{block, origin.id(), term};
	env.sign(sid, origin);
	return env;
}

}

// (plan 5.4) two assignments of one sequence to different records by one origin
TEST_CASE("equivocation proof", "[unit]") {
	auto const origin = crypto::generate_private_key();
	crypto::public_key_cache keys;
	keys.insert(origin.public_key());
	octet_vector const sid = securepath::test::random_octet_vector(8);
	test::test_block_creator one;
	test::test_block_creator two;
	auto const first = assigned(one.test_user_change(), origin, sid);
	auto const second = assigned(two.test_user_change(), origin, sid);
	REQUIRE(first.block().sequence() == second.block().sequence());
	REQUIRE(first.block().hash() != second.block().hash());

	equivocation_proof const proof{first, second};
	CHECK(!proof.verify(sid, keys));
	CHECK(proof.origin() == origin.id());
	CHECK(proof.sequence() == sequence_number{1});
	CHECK(proof.term() == 0);

	// the same record twice is no proof, nor are two sequences, two terms, another storage
	CHECK(equivocation_proof{first, first}.verify(sid, keys));
	CHECK(equivocation_proof{first, assigned(two.test_data_change(), origin, sid)}.verify(sid, keys));
	CHECK(equivocation_proof{first, assigned(two.test_user_change(), origin, sid, 1)}.verify(sid, keys));
	CHECK(proof.verify(securepath::test::random_octet_vector(8), keys));

	// a stranger's signature or an unknown origin
	auto const stranger = crypto::generate_private_key();
	keys.insert(stranger.public_key());
	CHECK(equivocation_proof{first, assigned(two.test_user_change(), stranger, sid)}.verify(sid, keys));
	crypto::public_key_cache no_keys;
	CHECK(proof.verify(sid, no_keys));

	// it travels as it is
	auto const copy = serialisation::asn_der_deserialise<equivocation_proof>(serialisation::asn_der_serialise(proof));
	CHECK(!copy.verify(sid, keys));
	CHECK(copy.first().block().hash() == first.block().hash());
	CHECK(copy.second().block().hash() == second.block().hash());
}

}
