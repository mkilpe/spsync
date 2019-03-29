#include "metadata.hpp"

namespace securepath::sync::util {

void metadata::insert(key_type const& key, octet_vector data) {
	data_[key] = std::move(data);
}

std::optional<octet_vector> metadata::find(key_type const& key) const {
	std::optional<octet_vector> ret;
	auto it = data_.find(key);
	if(it != data_.end()) {
		ret = it->second;
	}
	return ret;
}

void metadata::erase(key_type const& key) {
	data_.erase(key);
}

}