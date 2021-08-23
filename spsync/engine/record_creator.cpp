#include "record_creator.hpp"
#include "record_verifier.hpp"

#include <securepath/crypto/aes_gcm.hpp>
#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/print_util.hpp>

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

	//todo: when handling the change data, set the iv, tag et al here for data
	data_change_header header{std::move(meta)};

	add_change(std::move(header), std::move(data));
}

auth_record<data_change_record> data_change_record_creator::result() {
	return auth_record<data_change_record>{
		data_change_record{std::move(base_), std::move(changes_)},
		authentication_tag()};
}

void data_change_record_creator::add_change(data_change_header header, plain_single_change_data data) {
	// first authenticate the unencrypted data
	encryptor_->process_auth(serialisation::asn_der_serialise(data));

	// create encrypted header that contains the user's metadata
	encrypted_record_header<data_change_header> enc_header(encryptor_->process(serialisation::asn_der_serialise(header)));

	changes_.push_back(single_change{std::move(data), std::move(enc_header)});
}

void user_change_record_creator::set_change(users access, metadata meta) {
	set_data(user_change_header{{}, std::move(meta)}, plain_user_change_data{std::move(access)});
}

void user_change_record_creator::encrypt_last_key_for_users(crypto_context& cc) {
	crypto::enveloper e(serialisation::asn_der_serialise(env_structure{{cc.enc_keys().current_key()}}));
	for(auto v : plain_record_.access()) {
		auto key = cc.public_keys().find(v.user.public_key_id());
		if(!key) {
			LOG_WARN("could not make user change record because missing a public key for one of the users (kid=%)", v.user);
			throw make_error(crypto::errc::no_such_key, print("missing key for user '%'", v.user));
		}
		LOG_TRACE("enveloping current key for user %", v.user);
		e.add(*key);
	}
	plain_record_.set_enveloped_content(e.result());
}

void user_change_record_creator::set_data(user_change_header header, plain_user_change_data data) {
	plain_record_ = std::move(data);
	// the metadata is put into the encrypted header which is protected
	header_ = std::move(header);
}

auth_record<user_change_record> user_change_record_creator::result() {
	// first authenticate the unencrypted data
	encryptor_->process_auth(serialisation::asn_der_serialise(plain_record_));

	// create encrypted header that contains the user's metadata
	encrypted_record_header<user_change_header> enc_header(encryptor_->process(serialisation::asn_der_serialise(header_)));

	return auth_record<user_change_record>{
		user_change_record{std::move(base_), std::move(plain_record_), std::move(enc_header)},
		authentication_tag()};
}

auth_record<segment_record> segment_record_creator::result() {
	return auth_record<segment_record>{segment_record{}, authentication_tag()};
}

}
