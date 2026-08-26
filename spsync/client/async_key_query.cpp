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

void async_key_query::on_key(std::future<std::optional<crypto::public_key>> f) {
	LOG_TRACE("async_key_query::on_key");
	std::unique_lock l{mutex_};
	try {
		auto key = f.get();
		emit_result(error{}, key);
	} catch(error const& err) {
		LOG_WARN("error when querying key [err={}]", err);
		emit_result(err, std::nullopt);
	} catch(std::exception const& ex) {
		LOG_WARN("exception when querying key [ex={}]", ex.what());
		emit_result(make_error(securepath::errc::exception_occurred), std::nullopt);
	}
	next();
}

void async_key_query::on_connect() {
	LOG_TRACE("async_key_query::on_connect");
	std::unique_lock l{mutex_};
	if(!queries_.empty()) {
		client_.async_find_key(queries_.front().user.id().public_key_id()).then([&](auto f)
			{
				on_key(std::move(f));
			});
	} else {
		LOG_WARN("on_connect without queries?!");
		next();
	}
}

void async_key_query::on_disconnect(error err) {
	LOG_TRACE("async_key_query::on_disconnect [err={}]", err);
	std::unique_lock l{mutex_};
	if(!queries_.empty()) {
		callback_.emit<query_event>(err, std::nullopt, std::move(queries_.front().userdata));
		queries_.pop_front();
	}
	next();
}

void async_key_query::next() {
	LOG_TRACE("async_key_query::next [queue={}]", queries_.size());
	if(!queries_.empty()) {
		if(in_progress_ && queries_.front().user.key_server() == *in_progress_) {
			LOG_TRACE("same server, making query directly");
			client_.async_find_key(queries_.front().user.id().public_key_id()).then([&](auto f)
			{
				on_key(std::move(f));
			});
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
}

void async_key_query::query(user u, std::any userdata) {
	LOG_TRACE("async_key_query::query [kid={}, host={}, port={}]", u.id().public_key_id(), u.key_server().host, u.key_server().port);
	std::unique_lock l{mutex_};
	queries_.push_back({query_data{std::move(u), std::move(userdata)}});
	if(!in_progress_) {
		next();
	}
}

}
