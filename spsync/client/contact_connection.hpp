#pragma once

#include "types.hpp"
#include "contact_list.hpp"

#include <securepath/network/encryption/context.hpp>
#include <securepath/database/connection.hpp>
#include <securepath/event_system/event_handler.hpp>

namespace securepath::sync::client {

class contact_connection {
public:
	contact_connection(network::context&, event_system::event_handler& callback, database::connection_ptr);
	~contact_connection();

	void set_own_id(user);

	/// connect to the server
	void connect(host_port const& server);

	/// close connection
	void close();

	/// Add contact and send contacting packet
	std::unique_ptr<contact> add_contact(user receiver, std::string tag, octet_vector data);

	/// Get contact list
	contact_list& contacts();

	/// Emit pending events from database
	void emit_pending_events();

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
