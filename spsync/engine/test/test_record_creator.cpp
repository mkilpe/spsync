#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/engine/record_creator.hpp>
#include <securepath/crypto/aes_gcm.hpp>

namespace securepath::sync::util {

//encryption_key const& key, record_tag previous_tag, sequence_number last_seen

TEST_CASE("data_change_record_creator single", "[unit]") {
	encryption_key key{1, test::random_octet_vector(crypto::aes_gcm_key_size())};
	record_tag prevtag = to_octet_vector("test tag");
	data_change_record_creator creator(key, prevtag, sequence_number{1});

	object_id oid{to_octet_vector("test id")};
	record_tag prev_oid_tag{to_octet_vector("prev oid test tag")};
	metadata mdata{};

	// add the object change
	creator.add_change(oid, prevtag, mdata);

	auth_record<data_change_record> rec = creator.result();
	CHECK(rec.record.last_seen_sequence() == sequence_number{1});
	CHECK(rec.record.previous_tag() == prevtag);
	//CHECK(rec.record.)
	//t: check other data and cipher text
}

TEST_CASE("data_change_record_creator multi", "[unit]") {

}


TEST_CASE("user_change_record_creator", "[unit]") {

}


TEST_CASE("segment_record_creator", "[unit]") {

}

}
