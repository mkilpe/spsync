#ifndef SPSYNC_CORE_USER_CHANGE_RECORD_HEADER
#define SPSYNC_CORE_USER_CHANGE_RECORD_HEADER

#include "record_base.hpp"
#include "encrypted_record_header.hpp"
#include "../user_change_header.hpp"

#include <spsync/core/users.hpp>

namespace securepath::sync {

class plain_user_change_data {
public:
	plain_user_change_data(users access = {})
	: access_(std::move(access))
	{}

	/// get the user access changes
	users access() const { return access_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & access_ & trailing_data_;
	}
private:
	// the change in users access
	users access_;
	serialisation::trailing_data trailing_data_;
};

class user_change_record : public record_base {
public:
	user_change_record() = default;
	user_change_record(record_base base, plain_user_change_data data, encrypted_record_header<user_change_header> header)
	: record_base(std::move(base))
	, data_(std::move(data))
	, header_(std::move(header))
	{}

	/// Returns the user change data for this record
	plain_user_change_data data() const { return data_; }

	/// Returns the encrypted header
	encrypted_record_header<user_change_header> header() const { return header_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & data_ & header_;
	}
private:
	plain_user_change_data data_;
	encrypted_record_header<user_change_header> header_;
};

}

#endif
