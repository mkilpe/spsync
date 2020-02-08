#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/engine/record_creator.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/rsa.hpp>

namespace securepath::sync::util {

TEST_CASE("data_change_record_creator single", "[unit]") {
	encryption_key key{1, test::random_octet_vector(crypto::aes_gcm_key_size())};
	octet_vector prevhash = to_octet_vector("test tag");
	data_change_record_creator creator(key, chain_block_id{sequence_number{1}, prevhash});

	object_id oid{to_octet_vector("test id")};
	record_tag prev_oid_tag{to_octet_vector("prev oid test tag")};
	metadata mdata{{"test", to_octet_vector("data")}};

	// add the object change
	creator.add_change(oid, prev_oid_tag, mdata);

	auth_record<data_change_record> rec = creator.result();
	CHECK(rec.record.last_seen_block().sequence == sequence_number{1});
	CHECK(rec.record.last_seen_block().hash == prevhash);

	// verify authenticity and decrypt
	data_change_record_verifier ver(key, rec.record, rec.auth);
	CHECK(ver.is_authentic());
	REQUIRE(ver.headers().size() == 1);
	auto header = ver.headers().front();
	CHECK(header.data.id == oid);
	CHECK(header.data.previous_oid_record_tag == prev_oid_tag);
	CHECK(header.header.metadata() == mdata);
	CHECK(!header.header.data_info());
}

TEST_CASE("data_change_record_creator multi", "[unit]") {

}


TEST_CASE("user_change_record_creator", "[unit]") {
	encryption_key key{1, test::random_octet_vector(crypto::aes_gcm_key_size())};
	octet_vector prevhash = to_octet_vector("test tag");
	user_change_record_creator creator(key, chain_block_id{sequence_number{1}, prevhash});

	metadata mdata{{"test", to_octet_vector("data")}};

	crypto::private_key root_user_key{crypto::generate_rsa_private_key(1024)};
	util::user_id root_user{root_user_key.id()};
	users initial;
	initial.add(util::user_access{root_user, util::access_type::user_management_access});

	//set the user change for this record
	creator.set_change(initial, mdata);

	auth_record<user_change_record> rec = creator.result();
	CHECK(rec.record.last_seen_block().sequence == sequence_number{1});
	CHECK(rec.record.last_seen_block().hash == prevhash);

	// verify authenticity and decrypt
	user_change_record_verifier ver(key, rec.record, rec.auth);
	REQUIRE(ver.is_authentic());
	CHECK(ver.header().metadata() == mdata);
	CHECK(rec.record.data().access() == initial);
}


TEST_CASE("segment_record_creator", "[unit]") {

}

//t:
// - test manipulation causes verify failure
// - test data change with data
// - test user change with actual change info

}
