#include "chunk_crypto.hpp"

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/hash.hpp>
#include <securepath/crypto/hkdf.hpp>

namespace securepath::sync {
namespace {

void put_counter(octet_vector& out, std::uint64_t value) {
	for(int i = 7; i >= 0; --i) {
		out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
	}
}

}

octet_vector derive_data_key(octet_vector const& group_key, octet_vector const& nonce) {
	static constexpr char const info[] = "spsync record data key v1";
	octet_span const info_span{reinterpret_cast<std::uint8_t const*>(info), sizeof(info) - 1};
	return crypto::hkdf_sha3_512_derive_key(crypto::aes_gcm_key_size(), group_key, nonce, info_span);
}

octet_vector chunk_iv(std::uint64_t chunk_no) {
	octet_vector iv(crypto::aes_gcm_iv_size() - 8);
	put_counter(iv, chunk_no);
	return iv;
}

octet_vector chunk_aad(octet_vector const& nonce, std::uint64_t chunk_no) {
	octet_vector aad = nonce;
	put_counter(aad, chunk_no);
	return aad;
}

octet_vector encrypt_chunk(octet_vector const& data_key, octet_vector const& nonce, std::uint64_t chunk_no, octet_span plain) {
	auto enc = crypto::create_aes_gcm_stream_encryptor(data_key, chunk_iv(chunk_no));
	enc->process_auth(chunk_aad(nonce, chunk_no));
	octet_vector out(plain.size());
	enc->process(plain.data(), plain.data() + plain.size(), out.data());
	auto tag = enc->tag();
	out.insert(out.end(), tag.begin(), tag.end());
	return out;
}

std::optional<octet_vector> decrypt_chunk(octet_vector const& data_key, octet_vector const& nonce, std::uint64_t chunk_no, octet_span encrypted) {
	std::optional<octet_vector> ret;
	std::size_t const tag_size = chunk_tag_size();
	if(encrypted.size() >= tag_size) {
		auto dec = crypto::create_aes_gcm_stream_decryptor(data_key, chunk_iv(chunk_no));
		dec->process_auth(chunk_aad(nonce, chunk_no));
		octet_vector plain(encrypted.size() - tag_size);
		dec->process(encrypted.data(), encrypted.data() + plain.size(), plain.data());
		octet_vector const tag(encrypted.begin() + plain.size(), encrypted.end());
		if(crypto::tag_matches(dec->tag(), tag)) {
			ret = std::move(plain);
		}
	}
	return ret;
}

octet_vector chunk_digest(octet_span encrypted) {
	return crypto::hash(encrypted);
}

std::size_t chunk_tag_size() {
	return crypto::aes_gcm_tag_size();
}

}
