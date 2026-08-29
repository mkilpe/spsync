#include "users.hpp"

#include <format>

#include <securepath/serialisation/enum.hpp>

#include <cassert>

namespace securepath::sync {


serialisation::serialiser& serialise(serialisation::serialiser& s, users_change_mode const& v) {
	return securepath::serialisation::serialise(s, v);
}

serialisation::deserialiser& serialise(serialisation::deserialiser& s, users_change_mode& v) {
	return securepath::serialisation::serialise(s, v);
}

std::string to_string(users_change_mode const& mode) {
	if(mode == users_change_mode::full) {
		return "full";
	}
	if(mode == users_change_mode::delta) {
		return "delta";
	}
	return "unknown";
}

std::ostream& operator<<(std::ostream& out, users_change_mode const& mode) {
	return out << to_string(mode);
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

users& users::remove(util::user_id uid) {
	// first see if we have the same user already and replace that if we do
	auto it = users_.begin();
	for(;it != users_.end() && uid != it->user; ++it) {}
	if(it != users_.end()) {
		if(mode_ == users_change_mode::delta) {
			*it = util::user_access{uid, util::access_type::no_access};
		} else {
			users_.erase(it);
		}
	}
	else {
		if(mode_ == users_change_mode::delta) {
			users_.push_back(util::user_access{uid, util::access_type::no_access});
		}
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

bool users::empty() const {
	return users_.empty();
}

users_change_mode users::mode() const {
	return mode_;
}

bool users::operator==(users const& u) const {
	return mode_ == u.mode_ && users_ == u.users_ && trailing_data_ == u.trailing_data_;
}

std::string to_string(users const& u) {
	std::string out = std::format("{{mode={} users: ", u.mode());
	bool first = true;
	for(auto&& v : u.access()) {
		if(first) {
			first = false;
		} else {
			out += ", ";
		}
		out += std::format("{}", v);
	}
	out += "}";
	return out;
}

std::ostream& operator<<(std::ostream& out, users const& u) {
	return out << to_string(u);
}

}