#ifndef SPSYNC_CORE_USER_CHANGE_HEADER_HEADER
#define SPSYNC_CORE_USER_CHANGE_HEADER_HEADER

#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * Contains the information about the access change for users
 */
struct user_change_info {

	//todo: old encryption keys?
	//todo: new encryption key if user was removed?

	serialisation::trailing_data trailing_data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & trailing_data;
	}
};

/**
 * This is the encrypted header in the user_change_record
 *
 */
class user_change_header {
public:

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & user_change_ & metadata_ & trailing_data_;
	}
private:
	//contains the information about the access change for users
	user_change_info user_change_;

	//arbitrary metadata for higher layers
	util::metadata metadata_;
	serialisation::trailing_data trailing_data_;
};

}

#endif