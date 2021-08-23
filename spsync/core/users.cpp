#include "users.hpp"

#include <securepath/serialisation/enum.hpp>

#include <cassert>

namespace securepath::sync {


serialisation::serialiser& serialise(serialisation::serialiser& s, users_change_mode const& v) {
	return securepath::serialisation::serialise(s, v);
}

serialisation::deserialiser& serialise(serialisation::deserialiser& s, users_change_mode& v) {
	return securepath::serialisation::serialise(s, v);
}

std::ostream& operator<<(std::ostream& out, users_change_mode const& mode) {
	char const* const strings[] = {"full", "delta"};
	if(mode == users_change_mode::full) {
		out << "full";
	} else if(mode == users_change_mode::delta) {
		out << "delta";
	} else {
		out << "unknown";
	}
	return out;
}

users::users(users_change_mode mode)
: mode_(mode)
{
}

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

std::deque<util::user_access> const& users::access() const {
	return users_;
}

users::const_iterator users::begin() const {
	return users_.begin();
}

users::const_iterator users::end() const {
	return users_.end();
}

bool users::operator==(users const& u) const {
	return users_ == u.users_ && trailing_data_ == u.trailing_data_;
}

bool users::operator!=(users const& u) const {
	return !(*this == u);
}

std::ostream& operator<<(std::ostream& out, users const& u) {
	bool first = true;
	out << "{users: ";
	for(auto&& v : u.access()) {
		if(first) {
			first = false;
		} else {
			out << ", ";
		}
		out << v;
	}
	out << "}";
	return out;
}

}