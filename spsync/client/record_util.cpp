#include "record_util.hpp"

#include <spsync/engine/record_verifier.hpp>
#include <securepath/util/print_util.hpp>

namespace securepath::sync {

std::optional<util::metadata> extract_single_object_meta(encryption_key_storage const& keys, record_handle h) {
	std::optional<util::metadata> ret;
	auto record = h->record();
	auto obj_rec = record.deserialise_to<sync::data_change_record>();

	auto key = keys.find(obj_rec.encryption_key());
	if(!key) {
		sync::data_change_record_verifier ver(*key, obj_rec, record.auth());
		if(ver.is_authentic()) {
			if(ver.headers().size() == 1) {
				auto header = ver.headers().front().header;
				ret = header.metadata();
			} else {
				LOG_WARN("not a single change object");
			}
		} else {
			LOG_WARN("message not authentic");
		}
	} else {
		LOG_WARN("could not find key to decrypt message");
	}
	return ret;
}

plain_user_change_data encrypt_last_key_for_users(users const& us, crypto_context& cc) {
	plain_user_change_data ret(us);
	crypto::enveloper e(serialisation::asn_der_serialise(env_structure{{cc.enc_keys().current_key()}}));
	for(auto v : us) {
		auto key = cc.public_keys().find(v.user.public_key_id());
		if(!key) {
			LOG_WARN("could not make user change record because missing a public key for one of the users (kid=%)", v.user);
			throw make_error(crypto::errc::no_such_key, print("missing key for user '%'", v.user));
		}
		LOG_TRACE("enveloping current key for user %", v.user);
		e.add(*key);
	}
	ret.set_enveloped_content(e.result());
	return ret;
}


}
