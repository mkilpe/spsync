// SPDX-License-Identifier: MIT

#include "metadata.hpp"

namespace securepath::sync::util {

metadata::metadata(std::initializer_list<std::pair<key_type const, octet_vector>> list)
: data_(list)
{}

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

bool metadata::empty() const {
	return data_.empty();
}

bool metadata::operator==(metadata const& m) const {
	return data_ == m.data_ && trailing_data_ == m.trailing_data_;
}

}