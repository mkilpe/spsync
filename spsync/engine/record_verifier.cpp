#include "record_verifier.hpp"

#include <securepath/crypto/aes_gcm.hpp>

namespace securepath::sync {

record_verifier_base::record_verifier_base(encryption_key const& key, util::content_auth auth, record_base record)
: auth_(std::move(auth))
, base_(std::move(record))
, decryptor_(crypto::create_aes_gcm_stream_decryptor(key.key, base_.iv()))
{
	// authenticate the base first
	decryptor_->process_auth(serialisation::asn_der_serialise(base_));
}

bool record_verifier_base::is_authentic() const {
	return decryptor_->tag() == auth_.tag();
}


data_change_record_verifier::data_change_record_verifier(encryption_key const& key, auth_record<data_change_record> const& rec)
: record_verifier_base(key, rec)
{
	for(auto const& sheader : rec.record) {
		// first authenticate the unencrypted data
		decryptor_->process_auth(serialisation::asn_der_serialise(sheader.data));
		// decrypt the header
		headers_.push_back(
			single_data{
				sheader.data,
				serialisation::asn_der_deserialise<data_change_header>(decryptor_->process(sheader.header.data()))});
	}
}


user_change_record_verifier::user_change_record_verifier(encryption_key const& key, auth_record<user_change_record> const& rec)
: record_verifier_base(key, rec)
{
	// first authenticate the unencrypted data
	decryptor_->process_auth(serialisation::asn_der_serialise(rec.record.data()));
	// decrypt the header
	header_ = serialisation::asn_der_deserialise<user_change_header>(decryptor_->process(rec.record.header().data()));
}

user_change_header user_change_record_verifier::header() const {
	assert(header_);
	return *header_;
}

}
