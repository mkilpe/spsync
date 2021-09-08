#ifndef SPSYNC_CORE_USER_CHANGE_HEADER_HEADER
#define SPSYNC_CORE_USER_CHANGE_HEADER_HEADER

#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * Contains the information about the access change for users
 */
//q: is this needed at all?
struct user_change_info {

	user_change_info()
	{}

	// what here?
	//  * old encryption keys?

	serialisation::trailing_data trailing_data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq &  trailing_data;
	}
};


/**
 * This is the encrypted header in the user_change_record
 *
 */
class user_change_header {
public:
	user_change_header() = default;

	user_change_header(user_change_info uc_info, util::metadata meta)
	: user_change_(std::move(uc_info))
	, metadata_(std::move(meta))
	{}

	/// get the change info for users
	user_change_info change_info() const { return user_change_; }

	/// get the arbitrary metadata
	util::metadata metadata() const { return metadata_; }

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