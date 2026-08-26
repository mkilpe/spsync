#pragma once

#include "types.hpp"
#include <infrastructure/key_client/key_client.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/event_system/asio_broadcast_observer.hpp>
#include <securepath/network/encryption/context.hpp>

#include <any>

namespace securepath::sync::client {

struct query_event {
	typedef void type(error, std::optional<crypto::public_key>, std::any userdata);
};

struct query_data {
	util::user user;
	std::any userdata;
};

/**
 * Class to query keys asynchronously one at the time, in the order of requested queries
 */
class async_key_query {
public:
	async_key_query(network::context&, event_system::event_handler& callback);
	~async_key_query();

	void query(user, std::any userdata);
private:
	void emit_result(error, std::optional<crypto::public_key>);
	void on_connect();
	void on_disconnect(error err);
	void on_key(std::future<std::optional<crypto::public_key>> f);
	void next();
private:
	mutable std::mutex mutex_;
	std::optional<host_port> in_progress_;
	network::context& context_;
	event_system::event_handler& callback_;
	std::deque<query_data> queries_;
	key_client::client client_;
	event_system::asio_broadcast_observer observer_;
};

}

