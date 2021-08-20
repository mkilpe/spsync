#include "record_util.hpp"

#include <spsync/engine/record_verifier.hpp>

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

}
