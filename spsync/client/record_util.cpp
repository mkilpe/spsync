#include "record_util.hpp"

#include <spsync/engine/record_verifier.hpp>
#include <securepath/util/print_util.hpp>
#include <securepath/util/error.hpp>

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

search_data_records::search_data_records(crypto_context& cc)
: cc_(cc)
{
}

void search_data_records::ordering(record_order o) {
	ordering_ = o;
}

void search_data_records::only_in_sync(bool b) {
	only_in_sync_ = b;
}

//todo: implement only_in_sync_ option
std::deque<single_data_change> search_data_records::get(std::size_t max) {
	std::deque<single_data_change> res;

	if(!cur_seq_) {
		cur_seq_ = ordering_ == record_order::seq_ascending ?
			sequence_number{1} : cc_.records().last_block().sequence;
	}

	record_handle h;
	do {
		h = cc_.records().find(*cur_seq_);
		if(h) {
			if(h->type() == data_change_record_tag) {
				res.push_back(decrypt_data_record(h));
			}
			if(ordering_ == record_order::seq_ascending) {
				++*cur_seq_;
			} else {
				--*cur_seq_;
			}
		}
	} while(h && (!max || res.size() < max));

	return res;
}

single_data_change search_data_records::decrypt_data_record(record_handle rec) const {
	auto record = rec->record();
	auto obj_rec = record.deserialise_to<sync::data_change_record>();

	auto key = cc_.enc_keys().find(obj_rec.encryption_key());
	if(key) {
		sync::data_change_record_verifier ver(*key, obj_rec, record.auth());
		if(ver.is_authentic()) {
			if(ver.headers().size() == 1) {
				auto h = ver.headers().front();
				return single_data_change{
					h.data,
					h.header,
					record.sequence(),
					rec->internal_id()};
			} else {
				LOG_WARN("this version does not support multi-change records!");
			}
		} else {
			LOG_WARN("message not authentic");
		}
	} else {
		LOG_WARN("could not find key to decrypt message (seq=%)", obj_rec.encryption_key());
	}

	//t: better error handling
	throw make_error(securepath::errc::invalid_data, "bad record in record storage");
}

}
