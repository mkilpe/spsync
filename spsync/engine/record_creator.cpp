#include "record_creator.hpp"

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

record_creator_base::record_creator_base(encryption_key const& key, chain_block_id last_seen)
: base_(std::move(last_seen), crypto::random_octet_vector(crypto::aes_gcm_iv_size()), key.key_seq)
, encryptor_(crypto::create_aes_gcm_stream_encryptor(key.key, base_.iv()))
{
	// authenticate the base first
	encryptor_->process_auth(serialisation::asn_der_serialise(base_));
}

util::content_auth record_creator_base::authentication_tag() {
	return util::content_auth{encryptor_->tag()};
}


void data_change_record_creator::add_change(object_id oid, record_tag previous_oid_record_tag, metadata meta) {
	plain_single_change_data data{std::move(oid), std::move(previous_oid_record_tag)};

	// first authenticate the unencrypted data
	encryptor_->process_auth(serialisation::asn_der_serialise(data));

	//todo: when handling the change data, set the iv, tag et al here for data
	data_change_header header{std::move(meta)};

	// create encrypted header that contains the user's metadata
	encrypted_record_header<data_change_header> enc_header(encryptor_->process(serialisation::asn_der_serialise(header)));

	changes_.push_back(single_change{std::move(data), std::move(enc_header)});
}

auth_record<data_change_record> data_change_record_creator::result() {
	return auth_record<data_change_record>{
		data_change_record{std::move(base_), std::move(changes_)},
		authentication_tag()};
}


void user_change_record_creator::set_change(users access, metadata meta) {
	plain_record_ = plain_user_change_data{std::move(access)};

	// first authenticate the unencrypted data
	encryptor_->process_auth(serialisation::asn_der_serialise(plain_record_));

	// the metadata is put into the encrypted header which is protected
	meta_ = std::move(meta);
}

auth_record<user_change_record> user_change_record_creator::result() {
	user_change_header header{std::move(info_), std::move(meta_)};

	// create encrypted header that contains the user's metadata
	encrypted_record_header<user_change_header> enc_header(encryptor_->process(serialisation::asn_der_serialise(header)));

	return auth_record<user_change_record>{
		user_change_record{std::move(base_), std::move(plain_record_), std::move(enc_header)},
		authentication_tag()};
}

auth_record<segment_record> segment_record_creator::result() {
	return auth_record<segment_record>{segment_record{}, authentication_tag()};
}

}
