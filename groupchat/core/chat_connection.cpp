#include "chat_connection.hpp"

#include <flat_map>
#include "channel.hpp"
#include "events.hpp"

#include <spsync/comm/net_connection.hpp>

#include <securepath/event_system/event_handler.hpp>
#include <securepath/network/encryption/error.hpp>

#include <algorithm>
#include <filesystem>
#include <mutex>

namespace securepath::groupchat {

struct chat_connection::impl
: public event_system::event_handler
{
	impl(chat_conn_context context)
	: event_handler(context.callback.event_loop())
	, ccontext(context)
	, net(ccontext.context, *this)
	{
	}

	~impl() {
		stop_handler();
		net.close();
		decltype(channels){}.swap(channels);
	}

	channel& connect_to_storage(sync::storage_id const& cid) {
		assert(!cid.empty());
		auto it = channels.find(cid);
		if(it == channels.end()) {
			auto ret = channels.emplace(cid, std::make_unique<channel>(ccontext, cid));
			ret.first->second->init(cid, net);
			it = ret.first;
		}
		return *it->second;
	}

	channel& join_to_storage(sync::client::storage_info const& sinfo, std::string const& name) {
		auto it = channels.find(sinfo.sid);
		if(it != channels.end()) {
			LOG_WARN("chat already exists [cid={}]", to_hex(sinfo.sid));
			throw make_error(errc::invalid_state, "chat already exists");
		}

		auto ret = channels.emplace(sinfo.sid, std::make_unique<channel>(ccontext, sinfo.sid));
		ret.first->second->set_join_data(sinfo, name);

		ccontext.channels.add(sinfo.sid, ccontext.sync_server);

		ret.first->second->init(sinfo.sid, net);
		return *ret.first->second;
	}

	void on_connect() {
		reconnect_delay = initial_reconnect_delay;
		ccontext.callback.emit<events::on_connect>(ccontext.sid);
		if(promise_pending) {
			promise_pending = false;
			connect_promise.set_value();
		}
	}

	/**
	 * A failed attempt or a lost session: the next attempt goes to the next replica (plan
	 * 4.5) and is scheduled with a growing delay unless disconnect() stopped the connection
	 */
	void on_disconnect(error const& err) {
		LOG_INFO("sync server {} disconnected: {}", ccontext.sync_server, err);
		ccontext.callback.emit<events::on_disconnect>(ccontext.sid, err);
		if(promise_pending) {
			promise_pending = false;
			connect_promise.set_exception(std::make_exception_ptr(err));
		}
		next_server = (last_server + 1) % sync_endpoints().size();
		if(!stopped && !reconnect_timer) {
			LOG_INFO("reconnecting to {} in {} ms", sync_endpoints()[next_server], reconnect_delay.count());
			reconnect_timer = start_timer(reconnect_delay, true);
			reconnect_delay = std::min(reconnect_delay * 2, max_reconnect_delay);
		}
	}

	void on_timer(event_system::timer_handle handle) {
		if(handle == reconnect_timer) {
			reconnect_timer = {};
			if(!stopped) {
				try {
					connect();
				} catch(error const& err) {
					LOG_WARN("reconnect attempt failed to start: {}", err);
					on_disconnect(err);
				}
			}
		}
	}

	void stop() {
		stopped = true;
		if(reconnect_timer) {
			stop_timer(reconnect_timer);
			reconnect_timer = {};
		}
		net.close();
	}

	void on_create_storage(sync::storage_id const& cid, error err) {
		std::unique_lock l{mutex};
		assert(!cid.empty());
		auto it = channels.find(cid);
		if(it == channels.end()) {
			LOG_WARN("no channel found for chat: {}", to_hex(cid));
			err = make_error(securepath::errc::invalid_state, "chat room not set");
		} else if(!err) {
			try {
				it->second->init(cid, net);
				it->second->create_initial_record();
				// the chat exists on the server now: remember it
				ccontext.channels.add(cid, ccontext.sync_server);
			} catch(error const& e) {
				LOG_WARN("exception while initialising storage: {}", e);
				err = e;
			} catch(std::exception const& e) {
				LOG_WARN("exception while initialising storage: {}", e.what());
				err = make_error(securepath::errc::exception_occurred, e.what());
			}
		}
		if(err && it != channels.end()) {
			// a chat that never came to be on the server leaves nothing behind
			auto const path = it->second->db_path();
			channels.erase(it);
			std::error_code ec;
			std::filesystem::remove(path, ec);
		}
		l.unlock();
		ccontext.callback.emit<events::on_init>(server_chat_id{ccontext.sid, cid}, err);
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
				, event_dest<sync::events::on_connect>(&impl::on_connect)
				, event_dest<sync::events::on_disconnect>(&impl::on_disconnect)
				, event_dest<sync::events::on_create_storage>(&impl::on_create_storage)
				, event_dest<event_system::timer_event>(&impl::on_timer) );
	}

	channel& create_chat(std::string name, users members) {
		//check we have keys for the members (as otherwise on_create_storage will fail)
		for(auto&& m : members) {
			if(!ccontext.context.public_keys().find(m.user.public_key_id())) {
				LOG_WARN("cannot create chat because one of the member keys is missing [key={}]", m.user.public_key_id());
				throw make_error(crypto::errc::no_such_key, "cannot create chat, member key missing");
			}
		}
		// a home server with replicas carries the chat on all of them (plan 4.2/4.5)
		auto cid = net.create_storage(channel_storage_modes(!ccontext.fallback_sync_servers.empty()));
		auto ret = channels.emplace(cid, std::make_unique<channel>(ccontext, cid));
		ret.first->second->set_data(std::move(name), std::move(members));
		// recorded in the channel list once the server confirmed the creation (on_create_storage)
		return *ret.first->second;
	}

	/// endpoints in connection order: the primary followed by the fallback replicas
	std::vector<host_port> sync_endpoints() const {
		std::vector<host_port> eps{ccontext.sync_server};
		eps.insert(eps.end(), ccontext.fallback_sync_servers.begin(), ccontext.fallback_sync_servers.end());
		return eps;
	}

	/**
	 * Connect to the sync server (plan 4.5): the attempt goes to the replica next in the
	 * rotation, connection failures arrive asynchronously through on_disconnect which
	 * advances the rotation and schedules the next attempt.
	 */
	std::shared_future<void> connect() {
		stopped = false;
		if(promise_pending) {
			// an attempt is in flight (also the automatic reconnect): share its outcome
			return connect_future;
		}
		connect_promise = {};
		connect_future = connect_promise.get_future().share();
		promise_pending = true;
		std::chrono::seconds timeout{ccontext.config.get_default("network.timeout", 10).as_int64()};
		auto const eps = sync_endpoints();
		last_server = next_server % eps.size();
		LOG_INFO("connecting to sync server {} (replica {} of {})", eps[last_server], last_server + 1, eps.size());
		error err = net.connect(eps[last_server].host, eps[last_server].port, timeout);
		if(err) {
			promise_pending = false;
			if(make_error_code(network::errc::already_connected) == err.code()) {
				// connected already, just set the value
				connect_promise.set_value();
			} else {
				throw err;
			}
		}
		return connect_future;
	}

	host_port current_endpoint() const {
		return sync_endpoints()[last_server % sync_endpoints().size()];
	}

	static constexpr std::chrono::milliseconds initial_reconnect_delay{1000};
	static constexpr std::chrono::milliseconds max_reconnect_delay{30000};

	mutable std::mutex mutex;

	chat_conn_context ccontext;
	std::promise<void> connect_promise;
	std::shared_future<void> connect_future;
	bool promise_pending{};
	/// index of the sync endpoint the next connect() goes to and the one the last went to (plan 4.5)
	std::size_t next_server{};
	std::size_t last_server{};
	/// reconnect state: disconnect() stops it, a lost session restarts it with backoff
	bool stopped{true};
	event_system::timer_handle reconnect_timer{};
	std::chrono::milliseconds reconnect_delay{initial_reconnect_delay};

	std::flat_map<sync::storage_id, std::unique_ptr<channel>> channels;
	sync::network_connection net;
};

chat_connection::chat_connection(chat_conn_context context)
: impl_(std::make_unique<impl>(context))
{
}

chat_connection::~chat_connection()
{
}

std::shared_future<void> chat_connection::connect() {
	return impl_->connect();
}

void chat_connection::disconnect() {
	impl_->stop();
}

bool chat_connection::is_connected() const {
	return impl_->net.is_connected();
}

channel& chat_connection::create_chat(std::string name, users members) {
	std::unique_lock l{impl_->mutex};
	return impl_->create_chat(std::move(name), std::move(members));
}

channel& chat_connection::join(sync::client::storage_info const& sinfo, std::string const& name) {
	std::unique_lock l{impl_->mutex};
	return impl_->join_to_storage(sinfo, name);
}

channel& chat_connection::load(chat_id const& storage) {
	std::unique_lock l{impl_->mutex};
	return impl_->connect_to_storage(storage);
}

channel& chat_connection::get(chat_id const& storage) {
	std::unique_lock l{impl_->mutex};
	auto it = impl_->channels.find(storage);
	if(it == impl_->channels.end()) {
		throw std::runtime_error("no such storage");
	}
	return *it->second;
}

std::deque<chat_id> chat_connection::channel_ids() const {
	std::deque<chat_id> res;
	std::unique_lock l{impl_->mutex};
	for(auto const& v : impl_->channels) {
		res.push_back(v.first);
	}
	return res;
}

network::context& chat_connection::context() {
	return impl_->ccontext.context;
}

host_port chat_connection::end_point() const {
	return impl_->ccontext.sync_server;
}

host_port chat_connection::current_endpoint() const {
	return impl_->current_endpoint();
}

server_id chat_connection::id() const {
	return impl_->ccontext.sid;
}

}