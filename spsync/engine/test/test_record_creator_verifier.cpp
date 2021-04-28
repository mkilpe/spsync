#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/engine/record_creator.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/rsa.hpp>

namespace securepath::sync::util {

// + (1) create data change record with single change
// + (2) create user change record
// - (3) create data change record with multiple changes
// - (4) create segment record
// + (5) manipulation causes verify failure
// - (6) data change with data

// (1)
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

// (2)
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

// (3)
TEST_CASE("data_change_record_creator multi", "[unit]") {

}

// (4)
TEST_CASE("segment_record_creator", "[unit]") {

}

// (5)
TEST_CASE("record manipulation", "[unit]") {
	encryption_key key{1, test::random_octet_vector(crypto::aes_gcm_key_size())};
	octet_vector prevhash = to_octet_vector("test tag");
	data_change_record_creator creator(key, chain_block_id{sequence_number{1}, prevhash});

	object_id oid{to_octet_vector("test id")};
	record_tag prev_oid_tag{to_octet_vector("prev oid test tag")};
	metadata mdata{{"test", to_octet_vector("data")}};

	// add the object change
	creator.add_change(oid, prev_oid_tag, mdata);

	auth_record<data_change_record> rec = creator.result();
	octet_vector ser_rec = serialisation::asn_der_serialise_choice<record_types>(rec.record);

	for(int i = 0; i != 100; ++i) {

		auto manipulated = ser_rec;
		// manipulate the record, flip a random bit
		manipulated[test::random_uint32(0, manipulated.size()-1)] ^= 0x01;
		CHECK(manipulated != ser_rec);

		// reconstruct the auth record structure from the serialised and manipulated record
		try {
			data_change_record r = serialisation::asn_der_deserialise_choice<record_types, data_change_record>(manipulated
				, [](auto const& rec){ return rec; });
			auth_record<data_change_record> nrec(r, rec.auth);

			// in case we altered some serialisation related bit that didn't do anything, the records are equal
			if(serialisation::asn_der_serialise_choice<record_types>(nrec.record)
				!= serialisation::asn_der_serialise_choice<record_types>(rec.record)) {

				data_change_record_verifier ver(key, nrec.record, nrec.auth);
				CHECK(!ver.is_authentic());
			}
		} catch(serialisation::serialisation_error const&) {
			// if we happen to alter the serialisation header, deserialisation fails
		}
	}
}

}
