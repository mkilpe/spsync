#pragma once

#include "types.hpp"

#include <securepath/common/key_value_cache.hpp>

namespace securepath::groupchat {

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
