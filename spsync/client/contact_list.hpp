// SPDX-License-Identifier: MIT

#pragma once

#include "contact.hpp"
#include <securepath/database/connection.hpp>

namespace securepath::sync::client {

/// contact list
class contact_list {
public:
	contact_list(database::connection_ptr);

	std::deque<std::unique_ptr<contact>> enumerate() const;

	/// find a contact based on user_id
	std::unique_ptr<contact> find(user_id const&) const;

	/// add new contact
	std::unique_ptr<contact> add(user_id const&);

	/// remove existing contact
	void remove(user_id const&);
private:
	database::connection_ptr db_;
};

}
