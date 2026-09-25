// SPDX-License-Identifier: MIT

#include "member.hpp"

namespace securepath::sync {

std::string to_string(member_status s) {
	if(s == member_status::member) {
		return "member";
	} else if(s == member_status::pending_add) {
		return "pending_add";
	} else if(s == member_status::pending_remove) {
		return "pending_remove";
	}
	return "unknown";
}

member::member(util::user_id id, member_status s)
: id_(std::move(id))
, status_(s)
{
}

util::user_id member::id() const {
	return id_;
}

member_status member::status() const {
	return status_;
}

std::ostream& operator<<(std::ostream& out, member_status s) {
	return out << to_string(s);
}

}
