#pragma once

#include "contact_list.hpp"
#include "types.hpp"
#include "request_handler.hpp"

#include <securepath/network/encryption/context.hpp>
#include <securepath/database/connection.hpp>
#include <securepath/event_system/event_handler.hpp>

#include <memory>

namespace securepath::sync::client {

class contact_handler : public event_system::event_handler, public request_handler {
public:
	contact_handler(network::context&, event_system::event_handler& callback, database::connection_ptr);
	~contact_handler();

	/// Add contact and send packet
	std::unique_ptr<contact> add_contact(user receiver, std::string name, std::string message);

	/// Accept pending contact request
	std::unique_ptr<contact> accept_contact_request(request_id);

	/// Get contacts
	contact_list& contacts();

private:
	void on_connect();
	void on_disconnect(error err);
	void on_request(request const& req);

	void handle_event(std::unique_ptr<event_system::event_base> ev) override;
private:
	event_system::event_handler& callback_;
	contact_list contacts_;
};

}
