#pragma once

#include <spsync/core/users.hpp>

#include <securepath/common/key_value_cache.hpp>

namespace securepath::groupchat {

using user_id = sync::util::user_id;

/// GC contact
class contact : public key_value_cache {
public:
	contact(user_id id);

	/// user id of the member
	user_id id() const;
	std::string name() const;

	void set_name(std::string const& name);

private:
	user_id id_;
};

}
