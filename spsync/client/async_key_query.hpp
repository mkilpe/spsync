// SPDX-License-Identifier: MIT

#pragma once

#include "types.hpp"
#include <infrastructure/key_client/key_client.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/event_system/asio_broadcast_observer.hpp>
#include <securepath/network/encryption/context.hpp>

#include <any>
#include <coroutine>

namespace securepath::sync::client {

struct query_event {
	typedef void type(error, std::optional<crypto::public_key>, std::any userdata);
};

struct query_data {
	util::user user;
	std::any userdata;
};

/// fire and forget coroutine handle for the in-flight key query
struct detached_query {
	struct promise_type {
		detached_query get_return_object() { return {}; }
		std::suspend_never initial_suspend() noexcept { return {}; }
		std::suspend_never final_suspend() noexcept { return {}; }
		void return_void() {}
		[[noreturn]] void unhandled_exception() { std::terminate(); }
	};
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

	/// await one key lookup; must be started without holding the mutex (a ready future
	/// resumes inline)
	detached_query run_query(crypto::public_key_id kid);

	/// advance the queue under the lock; returns a key id to query once the lock is out
	std::optional<crypto::public_key_id> next_locked();
	void start_next(std::optional<crypto::public_key_id>);
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
