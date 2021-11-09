#pragma once

#include "types.hpp"

#include <securepath/common/key_value_cache.hpp>

namespace securepath::sync::client {

enum class contact_state {
	incomplete, //usually could not query the key yet
	complete
};

/// contact
class contact : public key_value_cache {
public:
	contact(user_id id);

	/// user id of the member
	user_id id() const;
	/// Name of the contact
	std::string name() const;
	/// Key server of the contact
	host_port server() const;
	/// State of the contact
	contact_state state() const;

	void set_name(std::string const& name);
	void set_server(host_port const& server);
	void set_state(contact_state);

private:
	user_id id_;
};

}
