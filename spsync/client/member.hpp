#pragma once

#include <spsync/core/users.hpp>
#include <spsync/util/format.hpp>

#include <securepath/common/key_value_cache.hpp>

#include <iosfwd>

namespace securepath::sync {

/// Status of the member
enum class member_status {
	member = 0,     /// member of the group, has committed user change
	pending_add,    /// locally added member that is waiting to be committed
	pending_remove  /// locally removed member that is waiting to be committed
};

std::string to_string(member_status);

/// Client side member of storage
class member : public key_value_cache {
public:
	member(util::user_id id, member_status);

	/// user id of the member
	util::user_id id() const;

	/// status of this member, if locally remove member, it is marked as pending and removed when record committed.
	member_status status() const;
private:
	util::user_id id_;
	member_status status_;
};

std::ostream& operator<<(std::ostream&, member_status);

}

SPSYNC_FORMAT_VIA_OSTREAM(securepath::sync::member_status)
