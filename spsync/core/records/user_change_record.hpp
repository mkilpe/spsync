#ifndef SPSYNC_CORE_USER_CHANGE_RECORD_HEADER
#define SPSYNC_CORE_USER_CHANGE_RECORD_HEADER

#include "record_base.hpp"
#include <spsync/core/users.hpp>

namespace securepath::sync {

class user_change_record : public record_base {
public:

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & access_ && header_ & trailing_data_;
	}
private:
	// the change in users access
	users access_;
	encrypted_record_header<user_change_header> header_;
	serialisation::trailing_data trailing_data_;
};

}

#endif
