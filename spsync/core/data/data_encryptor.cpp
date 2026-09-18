#include "data_encryptor.hpp"
#include "chunk_crypto.hpp"
#include "size_padding.hpp"

#include <spsync/core/error.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/util/error.hpp>

#include <algorithm>

namespace securepath::sync {

data_encryptor::data_encryptor(encryption_key const& group_key, std::uint32_t chunk_size, chunk_sink sink)
: nonce_(crypto::random_octet_vector(data_nonce_size))
, data_key_(derive_data_key(group_key.key, nonce_))
, chunk_size_(chunk_size)
, key_seq_(group_key.key_seq)
, sink_(std::move(sink))
{
	if(chunk_size_ == 0) {
		throw make_error(errc::invalid_configuration, "record data chunk size must not be zero");
	}
	buffer_.reserve(chunk_size_);
}

void data_encryptor::write(octet_span plain) {
	plain_size_ += plain.size();
	content_hash_.update(plain);
	consume(plain);
}

void data_encryptor::consume(octet_span bytes) {
	std::size_t pos = 0;
	while(pos < bytes.size()) {
		std::size_t const take = std::min<std::size_t>(chunk_size_ - buffer_.size(), bytes.size() - pos);
		if(buffer_.empty() && take == chunk_size_) {
			// a whole chunk straight from the caller's memory
			emit_chunk(bytes.subspan(pos, take));
		} else {
			buffer_.insert(buffer_.end(), bytes.begin() + pos, bytes.begin() + pos + take);
			if(buffer_.size() == chunk_size_) {
				emit_chunk(buffer_);
				buffer_.clear();
			}
		}
		pos += take;
	}
}

void data_encryptor::emit_chunk(octet_span plain) {
	auto encrypted = encrypt_chunk(data_key_, nonce_, chunks_, plain);
	manifest_.chunk_digests.push_back(chunk_digest(encrypted));
	enc_size_ += encrypted.size();
	sink_(chunks_, encrypted);
	++chunks_;
}

void data_encryptor::pad() {
	// RD11: zero padding inside the ciphertext up to the size class; the true length
	// travels in the encrypted header
	std::uint64_t left = padded_size(plain_size_, min_padded_data_size) - plain_size_;
	octet_vector const zeros(std::min<std::uint64_t>(left, chunk_size_));
	while(left != 0) {
		std::size_t const n = std::min<std::uint64_t>(left, zeros.size());
		consume(octet_span{zeros}.first(n));
		left -= n;
	}
}

encrypted_data_result data_encryptor::finish() {
	pad();
	if(!buffer_.empty()) {
		emit_chunk(buffer_);
		buffer_.clear();
	}
	encrypted_data_result ret;
	ret.descriptor = data_descriptor{enc_size_, chunk_size_, manifest_.digest()};
	ret.header = data_header{plain_size_, content_hash_.final(), nonce_, key_seq_, 0};
	ret.manifest = std::move(manifest_);
	manifest_ = {};
	return ret;
}

}
