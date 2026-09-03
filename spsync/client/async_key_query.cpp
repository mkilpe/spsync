#include "async_key_query.hpp"

#include <infrastructure/key_client/events.hpp>

namespace securepath::sync::client {

async_key_query::async_key_query(network::context& c, event_system::event_handler& callback)
: context_(c)
, callback_(callback)
, client_(context_)
, observer_(client_.event_handler(), context_.io_context())
{
	observer_.connect<key_client::events::on_connect>([&]{ on_connect(); });
	observer_.connect<key_client::events::on_disconnect>([&](error err){ on_disconnect(err); });
}

async_key_query::~async_key_query()
{
	observer_.disconnect_all();
	client_.close();
}

void async_key_query::emit_result(error err, std::optional<crypto::public_key> key) {
	LOG_TRACE("async_key_query::emit_result [err={}]", err);
	if(!queries_.empty()) {
		callback_.emit<query_event>(err, key, std::move(queries_.front().userdata));
		queries_.pop_front();
	}
}

detached_query async_key_query::run_query(crypto::public_key_id kid) {
	LOG_TRACE("async_key_query::run_query [kid={}]", kid);
	std::optional<crypto::public_key> key;
	error err;
	try {
		key = co_await client_.async_find_key(kid);
	} catch(error const& e) {
		LOG_WARN("error when querying key [err={}]", e);
		err = e;
	} catch(std::exception const& ex) {
		LOG_WARN("exception when querying key [ex={}]", ex.what());
		err = make_error(securepath::errc::exception_occurred);
	}

	std::optional<crypto::public_key_id> follow;
	{
		std::unique_lock l{mutex_};
		emit_result(err, std::move(key));
		follow = next_locked();
	}
	start_next(std::move(follow));
}

void async_key_query::on_connect() {
	LOG_TRACE("async_key_query::on_connect");
	std::optional<crypto::public_key_id> kid;
	{
		std::unique_lock l{mutex_};
		if(!queries_.empty()) {
			kid = queries_.front().user.id().public_key_id();
		} else {
			LOG_WARN("on_connect without queries?!");
			kid = next_locked();
		}
	}
	start_next(std::move(kid));
}

void async_key_query::on_disconnect(error err) {
	LOG_TRACE("async_key_query::on_disconnect [err={}]", err);
	std::optional<crypto::public_key_id> follow;
	{
		std::unique_lock l{mutex_};
		if(!queries_.empty()) {
			callback_.emit<query_event>(err, std::nullopt, std::move(queries_.front().userdata));
			queries_.pop_front();
		}
		follow = next_locked();
	}
	start_next(std::move(follow));
}

std::optional<crypto::public_key_id> async_key_query::next_locked() {
	LOG_TRACE("async_key_query::next [queue={}]", queries_.size());
	std::optional<crypto::public_key_id> kid;
	if(!queries_.empty()) {
		if(in_progress_ && queries_.front().user.key_server() == *in_progress_) {
			LOG_TRACE("same server, making query directly");
			kid = queries_.front().user.id().public_key_id();
		} else {
			client_.close();

			auto s = queries_.front().user.key_server();
			LOG_TRACE("async_key_query::next connecting to {}:{}", s.host, s.port);
			client_.connect(s.host, s.port);
			in_progress_ = s;
		}
	} else {
		client_.close();
		in_progress_ = std::nullopt;
	}
	return kid;
}

void async_key_query::start_next(std::optional<crypto::public_key_id> kid) {
	if(kid) {
		run_query(std::move(*kid));
	}
}

void async_key_query::query(user u, std::any userdata) {
	LOG_TRACE("async_key_query::query [kid={}, host={}, port={}]", u.id().public_key_id(), u.key_server().host, u.key_server().port);
	std::optional<crypto::public_key_id> follow;
	{
		std::unique_lock l{mutex_};
		queries_.push_back({query_data{std::move(u), std::move(userdata)}});
		if(!in_progress_) {
			follow = next_locked();
		}
	}
	start_next(std::move(follow));
}

}
