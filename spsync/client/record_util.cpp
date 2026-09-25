// SPDX-License-Identifier: MIT

#include "record_util.hpp"
#include <securepath/crypto/public_key_access.hpp>
#include <securepath/crypto/error.hpp>
#include <spsync/util/format.hpp>

#include <spsync/engine/record_verifier.hpp>
#include <securepath/util/print_util.hpp>
#include <securepath/util/error.hpp>

namespace securepath::sync {

plain_user_change_data encrypt_last_key_for_users(users const& us, crypto_context& cc) {
	plain_user_change_data ret(us);
	crypto::enveloper e(serialisation::asn_der_serialise(env_structure{{cc.enc_keys().current_key()}}));
	for(auto v : us) {
		auto key = cc.public_keys().find(v.user.public_key_id());
		if(!key) {
			LOG_WARN("could not make user change record because missing a public key for one of the users (kid={})", v.user);
			throw make_error(crypto::errc::no_such_key, std::format("missing key for user '{}'", v.user));
		}
		LOG_TRACE("enveloping current key for user {}", v.user);
		e.add(*key);
	}
	ret.set_enveloped_content(e.result());
	return ret;
}

error extract_single_data_changes(encryption_key_storage const& keys, record_handle rec, std::deque<single_data_change>& res) {
	error err;

	auto record = rec->record();
	auto obj_rec = record.deserialise_to<sync::data_change_record>();

	auto key = keys.find(obj_rec.encryption_key());
	if(key) {
		sync::data_change_record_verifier ver(*key, obj_rec, record.auth());
		if(ver.is_authentic()) {
			for(auto const& h : ver.headers()) {
				res.push_back(
					single_data_change{
						h.data,
						h.header,
						rec->block_id().sequence,
						rec->internal_id(),
						record.auth().signature_issuer()});
			}
		} else {
			LOG_WARN("message not authentic");
			err = make_error(errc::not_authentic);
		}
	} else {
		LOG_WARN("could not find key to decrypt message (seq={})", obj_rec.encryption_key());
		err = make_error(errc::no_encryption_key_found);
	}

	return err;
}

}
