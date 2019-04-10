#ifndef SPSYNC_CORE_USERS_HEADER
#define SPSYNC_CORE_USERS_HEADER

#include <spsync/core/types.hpp>
#include <spsync/util/user.hpp>

#include <deque>

namespace securepath::sync {


/**
 * Contains the users access rights (or delta thereof) for a storage chain
 *
 */
class users {
public:

	/// Adds user to this object and returns itself
	users& add(util::user_access);

	/// Merge another users object to this one
	void merge(users const&);

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & users_ & trailing_data_;
	}
private:
	// the access for users
	std::deque<util::user_access> users_;
	serialisation::trailing_data trailing_data_;
};

}

#endif