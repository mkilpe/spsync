#pragma once

#include "request.hpp"

#include <securepath/database/connection.hpp>

#include <deque>
#include <mutex>
#include <set>

namespace securepath::sync::client {

/// class to store ongoing requests
class request_storage {
public:
	request_storage(database::connection_ptr);

	/// get all the pending requests
	std::deque<db_request> enumerate(std::optional<request_state> = std::nullopt) const;

	/// find request with id
	std::optional<db_request> find(request_id) const;

	/// Change state of existing request / set error
	void change_state(request_id, request_state);

	/// add request, the returned id is used to find/remove it later on
	request_id add(request_data const&, packet_transport::transport_payload const&);

	/// remove request
	void remove(request_id);

	/// is user with given key id marked as banned sending requests
	bool is_sender_banned(crypto::public_key_id const&) const;

	/// mark sender key id banned
	void ban_sender(crypto::public_key_id const&);

private:
	database::connection_ptr db_;
	mutable std::mutex mutex_;
	mutable std::set<crypto::public_key_id> banned_;
};

}
