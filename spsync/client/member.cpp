#include "member.hpp"

namespace securepath::sync {

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

}
