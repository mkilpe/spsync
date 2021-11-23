#pragma once

#include "types.hpp"
#include "request_storage.hpp"

#include <securepath/network/encryption/context.hpp>
#include <securepath/database/connection.hpp>
#include <securepath/event_system/event_handler.hpp>

using namespace std::chrono_literals;

namespace securepath::sync::client {

class request_handler {
public:
	request_handler(network::context&, event_system::event_handler& callback, database::connection_ptr);
	~request_handler();

	void set_own_account(account_info);
	account_info own_account() const;

	/// connect to the server
	error connect(host_port const& server, std::chrono::seconds timeout = 10s);

	/// close connection
	void close();

	/// Send request packet
	void send_request(user receiver, std::string tag, octet_vector data);

	/// Try to re-evaluate request (eg. query missing key)
	void try_evaluate_request(request_id);

	/// Remove existing request
	void remove_request(request_id);

	/// Get request storage
	request_storage& requests();

	/// Emit pending events from database
	void emit_pending_requests();

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}
