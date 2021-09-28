#pragma once

#include "encryption_key_storage.hpp"
#include "record_storage.hpp"
#include <securepath/crypto/public_key_access.hpp>
#include <securepath/crypto/private_data_cache.hpp>

namespace securepath::sync {

class crypto_context {
public:
	crypto_context(crypto::public_key_access& pa
		, crypto::private_data_access& pd
		, encryption_key_storage& ek
		, record_storage& r)
	: public_keys_(pa)
	, private_data_(pd)
	, enc_keys_(ek)
	, records_(r)
	{}

	crypto::public_key_access& public_keys() const { return public_keys_; }
	crypto::private_data_access& private_data() const { return private_data_; }
	encryption_key_storage& enc_keys() const { return enc_keys_; }
	record_storage& records() const { return records_; }

private:
	crypto::public_key_access& public_keys_;
	crypto::private_data_access& private_data_;
	encryption_key_storage& enc_keys_;
	record_storage& records_;
};

}
