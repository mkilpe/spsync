// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/test/util.hpp>

#include <spsync/client/record_util.hpp>
#include <spsync/core/data/chunk_crypto.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/engine/record_creator.hpp>
#include <spsync/engine/record_verifier.hpp>
#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/crypto/public_key_cache.hpp>
#include <securepath/crypto/private_data_cache.hpp>

namespace securepath::sync::util {

using namespace securepath::test;

// + (1) create data change record with single change
// + (2) create user change record
// - (3) create data change record with multiple changes
// - (4) create segment record
// + (5) manipulation causes verify failure
// + (6) data change with data (RDS 1: descriptor halves)
// + (7) encrypted headers are padded to a size class and read back unpadded (RD11)
// + (8) a record of another structure version is not read

// (1)
TEST_CASE("data_change_record_creator single", "[unit]") {
	std::optional<crypto::private_key> signer = GENERATE(Catch::Generators::as<std::optional<crypto::private_key>>{}, std::nullopt, crypto::generate_private_key());

	encryption_key key{1, random_octet_vector(crypto::aes_gcm_key_size())};
	octet_vector prevhash = to_octet_vector("test tag");
	data_change_record_creator creator(key, chain_block_id{sequence_number{1}, prevhash}, signer);

	object_id oid{to_octet_vector("test id")};
	record_tag prev_oid_tag{to_octet_vector("prev oid test tag")};
	metadata mdata{{"test", to_octet_vector("data")}};

	// add the object change
	creator.add_change(oid, prev_oid_tag, mdata);

	auth_record<data_change_record> rec = creator.result();
	CHECK(rec.record.last_seen_block().sequence == sequence_number{1});
	CHECK(rec.record.last_seen_block().hash == prevhash);

	if(signer) {
		crypto::public_key_cache keys;
		keys.insert(signer->public_key());
		CHECK(rec.auth.has_signature());
		CHECK(!rec.auth.verify(keys, serialisation::asn_der_serialise_choice<record_types>(rec.record)));
	} else {
		CHECK(!rec.auth.has_signature());
	}

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

	crypto::public_key_cache keycache;
	crypto::private_data_cache datacache;
	auto db = test::create_test_database();
	encryption_key_storage kstorage(db);
	record_storage rstorage(db);
	crypto_context crypto{keycache, datacache, kstorage, rstorage};

	encryption_key key{1, random_octet_vector(crypto::aes_gcm_key_size())};
	kstorage.insert(key);

	octet_vector prevhash = to_octet_vector("test tag");
	user_change_record_creator creator(key, chain_block_id{sequence_number{1}, prevhash});

	metadata mdata{{"test", to_octet_vector("data")}};

	crypto::private_key root_user_key{crypto::generate_private_key()};
	keycache.insert(root_user_key.public_key());

	util::user_id root_user{root_user_key.id()};
	users initial;
	initial.add(util::user_access{root_user, util::access_type::user_management_access});

	//set the user change for this record
	creator.set_change(encrypt_last_key_for_users(initial, crypto), mdata);

	auth_record<user_change_record> rec = creator.result();
	CHECK(rec.record.last_seen_block().sequence == sequence_number{1});
	CHECK(rec.record.last_seen_block().hash == prevhash);
	CHECK(!rec.record.data().enveloped_content().empty());

	// verify authenticity and decrypt
	user_change_record_verifier ver(key, rec.record, rec.auth);
	REQUIRE(ver.is_authentic());
	CHECK(ver.header().metadata() == mdata);
	CHECK(rec.record.data().access() == initial);

	auto env = rec.record.data().enveloped_content();
	auto data = serialisation::asn_der_deserialise<env_structure>(env.decrypt(root_user_key));
	REQUIRE(data.enc_keys.size() == 1);
	CHECK(data.enc_keys.front() == key);
}

// (3)
TEST_CASE("data_change_record_creator multi", "[unit]") {

}

// (4)
TEST_CASE("segment_record_creator", "[unit]") {

}

// (5)
TEST_CASE("record manipulation", "[unit]") {
	encryption_key key{1, random_octet_vector(crypto::aes_gcm_key_size())};
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
		manipulated[random_uint32(0, manipulated.size()-1)] ^= 0x01;
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


namespace {

encryption_key test_key() {
	return encryption_key{1, random_octet_vector(crypto::aes_gcm_key_size())};
}

/// a single-change record whose metadata carries a payload of the given size
auth_record<data_change_record> record_with_payload(encryption_key const& key, std::size_t payload) {
	data_change_record_creator creator(key, chain_block_id{sequence_number{1}, to_octet_vector("tag")});
	creator.add_change(object_id{to_octet_vector("oid")}, {}, metadata{{"payload", random_octet_vector(payload)}});
	return creator.result();
}

std::size_t header_size(auth_record<data_change_record> const& rec) {
	return rec.record.begin()->header.data().size();
}

}

// (6)
TEST_CASE("data_change_record_creator with data descriptor", "[unit]") {
	auto key = test_key();
	data_descriptor desc{123456, 4096, random_octet_vector(64)};
	data_header dh{100000, random_octet_vector(64), random_octet_vector(data_nonce_size), sequence_number{1}, 0};

	data_change_record_creator creator(key, chain_block_id{sequence_number{1}, to_octet_vector("tag")});
	object_id oid{to_octet_vector("oid")};
	creator.add_change(oid, {}, metadata{{"name", to_octet_vector("file")}}, desc, dh);
	creator.add_change(object_id{to_octet_vector("other")}, {}, metadata{});
	auto rec = creator.result();

	// the plain half is visible without the key, the secret half only after decryption
	REQUIRE(std::distance(rec.record.begin(), rec.record.end()) == 2);
	CHECK(rec.record.begin()->data.data == desc);
	CHECK(!std::next(rec.record.begin())->data.data);

	data_change_record_verifier ver(key, rec.record, rec.auth);
	REQUIRE(ver.is_authentic());
	auto headers = ver.headers();
	REQUIRE(headers.size() == 2);
	CHECK(headers[0].data.data == desc);
	CHECK(headers[0].header.data_info() == dh);
	CHECK(headers[0].header.metadata().find("name") == to_octet_vector("file"));
	CHECK(!headers[1].data.data);
	CHECK(!headers[1].header.data_info());

	// the descriptor is authenticated: a changed size fails the record
	auto tampered = rec;
	data_change_record forged{static_cast<record_base const&>(rec.record)};
	for(auto const& c : rec.record) {
		auto change = c;
		if(change.data.data) {
			change.data.data->enc_size += 1;
		}
		forged.add(change);
	}
	CHECK(!data_change_record_verifier(key, forged, rec.auth).is_authentic());
}

// (7)
TEST_CASE("encrypted record headers pad to size classes", "[unit]") {
	auto key = test_key();
	// short payloads all look the same, a longer one falls into another class
	auto small = record_with_payload(key, 10);
	auto medium = record_with_payload(key, 150);
	auto large = record_with_payload(key, 900);
	CHECK(header_size(small) == header_size(medium));
	CHECK(header_size(small) < header_size(large));
	CHECK(header_size(small) >= min_padded_header_size);

	// readers never see the padding
	for(auto const* rec : {&small, &medium, &large}) {
		data_change_record_verifier ver(key, rec->record, rec->auth);
		REQUIRE(ver.is_authentic());
		auto meta = ver.headers().front().header.metadata();
		auto payload = meta.find("payload");
		REQUIRE(payload);
		CHECK(payload->size() == (rec == &small ? 10u : rec == &medium ? 150u : 900u));
	}
}

// (8)
TEST_CASE("record of another structure version is not read", "[unit]") {
	auto key = test_key();
	auto rec = record_with_payload(key, 10);
	CHECK(rec.record.structure_version() == record_base::current_structure_version);

	// rewrite the version integer (the first field of the base, the first field of the
	// record) to 1 and read the record back
	auto der = serialisation::asn_der_serialise(rec.record);
	octet_vector const current{0x02, 0x01, static_cast<std::uint8_t>(record_base::current_structure_version)};
	auto it = std::search(der.begin(), der.end(), current.begin(), current.end());
	REQUIRE(it != der.end());
	it[2] = 1;
	auto old = serialisation::asn_der_deserialise<data_change_record>(der);
	REQUIRE(old.structure_version() == 1);

	data_change_record_verifier ver(key, old, rec.auth);
	CHECK(!ver.supported());
	CHECK(!ver.is_authentic());
	CHECK(ver.headers().empty());
}

}
