#include "users.hpp"

#include <cassert>

namespace securepath::sync {

users& users::add(util::user_access access) {
	// first see if we have the same user already and replace that if we do
	auto it = users_.begin();
	for(;it != users_.end() && access.user != it->user; ++it) {}
	if(it != users_.end()) {
		*it = std::move(access);
	}
	else {
		users_.push_back(std::move(access));
	}
	return *this;
}

void users::merge(users const&) {
	//implement
	assert(false);
}

}