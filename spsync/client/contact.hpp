#pragma once

#include "types.hpp"

#include <securepath/common/key_value_cache.hpp>

namespace securepath::sync::client {

enum class contact_state {
	request,
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
	/// Get contacting data if any set
	std::optional<octet_vector> contacting_data() const;

	void set_name(std::string const& name);
	void set_server(host_port const& server);
	void set_state(contact_state);
	void set_contacting_data(octet_vector const&);

private:
	user_id id_;
};

}
