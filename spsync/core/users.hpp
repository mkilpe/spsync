// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/types.hpp>
#include <spsync/util/format.hpp>
#include <spsync/util/user.hpp>

#include <securepath/serialisation/deque.hpp>

#include <deque>

namespace securepath::sync {

/// mode in which the users class operates
enum class users_change_mode {
	full  = 1, /// the users class contains all users
	delta = 2  /// the users class contains only changed users
};

serialisation::serialiser& serialise(serialisation::serialiser& s, users_change_mode const& v);
serialisation::deserialiser& serialise(serialisation::deserialiser& s, users_change_mode& v);

std::string to_string(users_change_mode const&);
std::ostream& operator<<(std::ostream&, users_change_mode const&);

/**
 * Contains the users access rights (or delta thereof) for a storage chain
 *
 */
class users {
public:
	users(users_change_mode mode = users_change_mode::full);

	/// Adds user and returns itself
	users& add(util::user_access);

	/// Removes user and returns itself
	users& remove(util::user_id);

	/// Get the users
	std::deque<util::user_access> const& access() const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & mode_ & users_ & trailing_data_;
	}

	bool operator==(users const&) const;

	using const_iterator = std::deque<util::user_access>::const_iterator;
	const_iterator begin() const;
	const_iterator end() const;

	bool empty() const;

	users_change_mode mode() const;
private:
	// the access for users
	users_change_mode mode_;
	std::deque<util::user_access> users_;
	serialisation::trailing_data trailing_data_;
};

std::string to_string(users const&);
std::ostream& operator<<(std::ostream&, users const&);

}


SPSYNC_FORMAT_VIA_TO_STRING(securepath::sync::users)
SPSYNC_FORMAT_VIA_TO_STRING(securepath::sync::users_change_mode)

