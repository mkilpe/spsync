// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <spsync/test/test_record_data.hpp>

#include <spsync/core/data/chunk_crypto.hpp>
#include <spsync/core/data/data_decryptor.hpp>
#include <spsync/core/data/data_encryptor.hpp>
#include <spsync/core/data/size_padding.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/records/encrypted_record_header.hpp>
#include <spsync/util/object_id.hpp>

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/hash.hpp>

#include <map>

namespace securepath::sync {
namespace {

using test::test_group_key;

/// encrypt plain in pieces, collect the chunks
struct encrypted_data {
	encrypted_data_result result;
	std::map<std::uint64_t, octet_vector> chunks;
};

encrypted_data encrypt_all(encryption_key const& key, octet_vector const& plain, std::uint32_t chunk_size, std::size_t piece = 1000) {
	encrypted_data ret;
	data_encryptor enc(key, chunk_size, [&](std::uint64_t no, octet_vector const& c) { ret.chunks[no] = c; });
	for(std::size_t pos = 0; pos < plain.size(); pos += piece) {
		enc.write(octet_span{plain}.subspan(pos, std::min(piece, plain.size() - pos)));
	}
	ret.result = enc.finish();
	return ret;
}

/// decrypt every chunk in order, nullopt when one fails
std::optional<octet_vector> decrypt_all(encryption_key const& key, encrypted_data const& d) {
	data_decryptor dec(key, d.result.descriptor, d.result.header);
	octet_vector out;
	bool ok = d.chunks.size() == dec.chunk_count();
	for(std::uint64_t no = 0; ok && no < dec.chunk_count(); ++no) {
		auto plain = dec.decrypt(no, d.chunks.at(no));
		ok = plain.has_value();
		if(ok) {
			out.insert(out.end(), plain->begin(), plain->end());
		}
	}
	return ok ? std::optional{out} : std::nullopt;
}

}

// RD11: size classes keep a few significant bits, floor applies below it
TEST_CASE("size padding classes", "[unit]") {
	static_assert(padded_size(0, 4096) == 4096);
	static_assert(padded_size(4096, 4096) == 4096);
	static_assert(padded_size(4097, 4096) == 4352);
	static_assert(padded_size(1000000, 4096) == 1015808);
	static_assert(padded_size(100000000, 4096) == 100663296);
	static_assert(padded_size(60, 256) == 256);
	static_assert(padded_size(300, 256) == 304);
	static_assert(padded_size(129, 0) == 144);
	static_assert(padded_size(1, 0) == 1);

	// never shrinks, overhead bounded, monotonic
	std::uint64_t previous = 0;
	for(std::uint64_t size = 4000; size < 300000; size += 97) {
		auto p = padded_size(size, min_padded_data_size);
		REQUIRE(p >= size);
		REQUIRE(p <= size + size / 8);
		REQUIRE(p >= previous);
		previous = p;
	}
}

// RD3: chunk crypto binds a chunk to its data (nonce) and position (counter)
TEST_CASE("chunk crypto binds nonce and position", "[unit]") {
	auto key = test_group_key();
	octet_vector nonce = securepath::test::random_octet_vector(data_nonce_size);
	octet_vector other_nonce = securepath::test::random_octet_vector(data_nonce_size);
	auto data_key = derive_data_key(key.key, nonce);
	CHECK(data_key.size() == crypto::aes_gcm_key_size());
	CHECK(data_key != derive_data_key(key.key, other_nonce));
	CHECK(data_key == derive_data_key(key.key, nonce));

	octet_vector plain = securepath::test::random_octet_vector(5000);
	auto encrypted = encrypt_chunk(data_key, nonce, 7, plain);
	CHECK(encrypted.size() == plain.size() + chunk_tag_size());
	CHECK(decrypt_chunk(data_key, nonce, 7, encrypted) == plain);
	// wrong position, wrong data, wrong key, tampered byte, truncated
	CHECK(!decrypt_chunk(data_key, nonce, 8, encrypted));
	CHECK(!decrypt_chunk(data_key, other_nonce, 7, encrypted));
	CHECK(!decrypt_chunk(derive_data_key(key.key, other_nonce), nonce, 7, encrypted));
	auto tampered = encrypted;
	tampered[100] ^= 1;
	CHECK(!decrypt_chunk(data_key, nonce, 7, tampered));
	CHECK(!decrypt_chunk(data_key, nonce, 7, octet_span{encrypted}.first(chunk_tag_size() - 1)));
	// same input encrypts the same only with the same nonce and position
	CHECK(encrypt_chunk(data_key, nonce, 7, plain) == encrypted);
	CHECK(encrypt_chunk(data_key, nonce, 8, plain) != encrypted);
}

// RD2/RD3/RD11: stream in, chunks out, manifest verifies, decrypts back, padding stripped
TEST_CASE("record data round trip", "[unit]") {
	auto key = test_group_key(5);
	std::uint32_t const chunk_size = 4096;
	auto size = GENERATE(0u, 1u, 4095u, 4096u, 4097u, 3 * 4096u + 5, 40000u);
	octet_vector plain = securepath::test::random_octet_vector(size);

	auto d = encrypt_all(key, plain, chunk_size, 777);
	auto const& desc = d.result.descriptor;
	auto const& header = d.result.header;
	CHECK(header.plain_size == size);
	CHECK(header.content_digest == crypto::hash(plain));
	CHECK(header.nonce.size() == data_nonce_size);
	CHECK(header.key_seq == sequence_number{5});
	CHECK(desc.chunk_size == chunk_size);
	// padded inside the ciphertext to the size class
	std::uint64_t const padded = padded_size(size, min_padded_data_size);
	std::uint64_t const expected_chunks = (padded + chunk_size - 1) / chunk_size;
	CHECK(desc.chunk_count() == expected_chunks);
	CHECK(d.chunks.size() == expected_chunks);
	CHECK(desc.enc_size == padded + expected_chunks * chunk_tag_size());
	// the manifest is what the descriptor commits to
	CHECK(d.result.manifest.matches(desc));
	CHECK(desc.manifest_digest == d.result.manifest.digest());
	for(auto const& [no, chunk] : d.chunks) {
		CHECK(d.result.manifest.verify_chunk(no, chunk));
	}
	// and it all comes back
	CHECK(decrypt_all(key, d) == plain);

	// two encryptions of the same content are unrelated to an observer (fresh nonce)
	auto again = encrypt_all(key, plain, chunk_size);
	CHECK(again.result.descriptor.manifest_digest != desc.manifest_digest);
	CHECK(again.result.header.content_digest == header.content_digest);
}

// the server-side checks: tamper, reorder, foreign manifest, transplant
TEST_CASE("record data manifest catches tampering", "[unit]") {
	auto key = test_group_key();
	std::uint32_t const chunk_size = 4096;
	octet_vector plain = securepath::test::random_octet_vector(3 * chunk_size + 100);
	auto d = encrypt_all(key, plain, chunk_size);
	auto other = encrypt_all(key, securepath::test::random_octet_vector(2 * chunk_size), chunk_size);
	REQUIRE(d.chunks.size() == 4);

	// a flipped byte fails the manifest and the tag
	auto tampered = d;
	tampered.chunks[2][10] ^= 0x80;
	CHECK(!d.result.manifest.verify_chunk(2, tampered.chunks[2]));
	CHECK(!decrypt_all(key, tampered));

	// swapped chunks fail by position on both sides
	auto swapped = d;
	std::swap(swapped.chunks[0], swapped.chunks[1]);
	CHECK(!d.result.manifest.verify_chunk(0, swapped.chunks[0]));
	CHECK(!decrypt_all(key, swapped));

	// another data's manifest or chunk does not fit
	CHECK(!other.result.manifest.matches(d.result.descriptor));
	CHECK(!d.result.manifest.verify_chunk(1, other.chunks[1]));
	auto transplanted = d;
	transplanted.chunks[1] = other.chunks[1];
	CHECK(!decrypt_all(key, transplanted));

	// a manifest with a chunk missing does not match the descriptor even if the digest did
	data_manifest shorter = d.result.manifest;
	shorter.chunk_digests.pop_back();
	CHECK(!shorter.matches(d.result.descriptor));

	// the wrong group key derives the wrong data key
	CHECK(!decrypt_all(test_group_key(), d));
}

// random access: any chunk alone, the padding stripped from the last ones
TEST_CASE("record data random access", "[unit]") {
	auto key = test_group_key();
	std::uint32_t const chunk_size = 4096;
	std::uint64_t const size = 2 * chunk_size + 10;
	octet_vector plain = securepath::test::random_octet_vector(size);
	auto d = encrypt_all(key, plain, chunk_size);
	data_decryptor dec(key, d.result.descriptor, d.result.header);
	// 8202 pads to 8704: three chunks, the last one 10 bytes of data and padding
	REQUIRE(dec.chunk_count() == 3);
	CHECK(dec.chunk_plain_size(0) == chunk_size);
	CHECK(dec.chunk_plain_size(1) == chunk_size);
	CHECK(dec.chunk_plain_size(2) == 10);
	CHECK(dec.chunk_plain_size(3) == 0);
	auto last = dec.decrypt(2, d.chunks[2]);
	REQUIRE(last);
	CHECK(*last == octet_vector(plain.begin() + 2 * chunk_size, plain.end()));
	auto middle = dec.decrypt(1, d.chunks[1]);
	REQUIRE(middle);
	CHECK(*middle == octet_vector(plain.begin() + chunk_size, plain.begin() + 2 * chunk_size));
	CHECK(!dec.decrypt(3, d.chunks[2]));
}

// RD2: both descriptor halves serialise inside their records
TEST_CASE("data descriptor round trip in records", "[unit]") {
	data_descriptor desc{123456, 4096, securepath::test::random_octet_vector(64)};
	data_header header{100000, securepath::test::random_octet_vector(64),
		securepath::test::random_octet_vector(data_nonce_size), sequence_number{4}, 0};

	// (through single_change: object_id's explicit constructor keeps the plain struct out
	// of the deserialise helper's value-initialisation check)
	single_change change{plain_single_change_data{util::create_object_id(), securepath::test::random_octet_vector(16), desc}};
	auto change_back = serialisation::asn_der_deserialise<single_change>(serialisation::asn_der_serialise(change)).data;
	CHECK(change_back.id == change.data.id);
	CHECK(change_back.previous_oid_record_tag == change.data.previous_oid_record_tag);
	CHECK(change_back.data == desc);
	// without data the field is absent
	single_change plain_change{plain_single_change_data{util::create_object_id(), {}}};
	CHECK(!serialisation::asn_der_deserialise<single_change>(serialisation::asn_der_serialise(plain_change)).data.data);

	data_change_header dh{util::metadata{}, header};
	auto dh_back = serialisation::asn_der_deserialise<data_change_header>(serialisation::asn_der_serialise(dh));
	CHECK(dh_back.data_info() == header);
	CHECK(!serialisation::asn_der_deserialise<data_change_header>(serialisation::asn_der_serialise(data_change_header{util::metadata{}})).data_info());

	data_manifest manifest{{securepath::test::random_octet_vector(64), securepath::test::random_octet_vector(64)}};
	CHECK(serialisation::asn_der_deserialise<data_manifest>(serialisation::asn_der_serialise(manifest)) == manifest);
}

// RD11: the encrypted header plaintext is padded to a size class and unpadded on read
TEST_CASE("record header padding classes", "[unit]") {
	auto sizes = {0u, 10u, 200u, 255u, 256u, 257u, 300u, 1000u, 5000u};
	for(auto size : sizes) {
		octet_vector header = securepath::test::random_octet_vector(size);
		auto padded = pad_record_header(header);
		CHECK(unpad_record_header(padded) == header);
		// the padded plaintext holds exactly the size class (plus the small structure overhead)
		std::uint64_t const target = padded_size(size, min_padded_header_size);
		CHECK(padded.size() >= target);
		CHECK(padded.size() <= target + 24);
	}
	// every short header pads to the same length
	CHECK(pad_record_header(octet_vector(10)).size() == pad_record_header(octet_vector(200)).size());
	CHECK(pad_record_header(octet_vector(257)).size() == pad_record_header(octet_vector(270)).size());
	CHECK(pad_record_header(octet_vector(200)).size() != pad_record_header(octet_vector(300)).size());
}

}
