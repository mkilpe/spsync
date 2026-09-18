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
	return supported() && decryptor_->tag() == auth_.tag();
}


data_change_record_verifier::data_change_record_verifier(encryption_key const& key, data_change_record const& rec, util::content_auth auth)
: record_verifier_base(key, std::move(auth), rec)
{
	// the headers of another structure version do not parse: leave them (not authentic)
	for(auto it = rec.begin(); supported() && it != rec.end(); ++it) {
		// first authenticate the unencrypted data
		decryptor_->process_auth(serialisation::asn_der_serialise(it->data));
		// decrypt the header
		headers_.push_back(
			single_data{
				it->data,
				serialisation::asn_der_deserialise<data_change_header>(unpad_record_header(decryptor_->process(it->header.data())))});
	}
}


user_change_record_verifier::user_change_record_verifier(encryption_key const& key, user_change_record const& rec, util::content_auth auth)
: record_verifier_base(key, std::move(auth), rec)
{
	// first authenticate the unencrypted data
	decryptor_->process_auth(serialisation::asn_der_serialise(rec.data()));
	// decrypt the header (not for another structure version: it would not parse)
	if(supported()) {
		header_ = serialisation::asn_der_deserialise<user_change_header>(unpad_record_header(decryptor_->process(rec.header().data())));
	}

	data_ = rec.data();
}

user_change_header user_change_record_verifier::header() const {
	assert(header_);
	return *header_;
}

plain_user_change_data user_change_record_verifier::data() const {
	return data_;
}

segment_record_verifier::segment_record_verifier(encryption_key const& key, segment_record const& rec, util::content_auth auth)
: record_verifier_base(key, std::move(auth), rec)
{
	// first authenticate the unencrypted data
	data_ = rec.data();
	decryptor_->process_auth(serialisation::asn_der_serialise(data_));
	// decrypt the header (not for another structure version: it would not parse)
	if(supported()) {
		header_ = serialisation::asn_der_deserialise<segment_header>(unpad_record_header(decryptor_->process(rec.header().data())));
	}
}

segment_header segment_record_verifier::header() const {
	assert(header_);
	return *header_;
}

plain_segment_data const& segment_record_verifier::data() const {
	return data_;
}

}
