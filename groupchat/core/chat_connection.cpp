#include "chat_connection.hpp"
#include "channel.hpp"
#include "events.hpp"

#include <spsync/comm/net_connection.hpp>

#include <securepath/event_system/event_handler.hpp>
#include <securepath/network/encryption/error.hpp>

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

	void on_connect() {
		ccontext.callback.emit<events::on_connect>(ccontext.sid);
		connect_promise.set_value();
	}

	void on_disconnect(error const& err) {
		ccontext.callback.emit<events::on_disconnect>(ccontext.sid, err);
		connect_promise.set_exception(std::make_exception_ptr(err));
	}

	void on_create_storage(sync::storage_id const& cid, error err) {
		if(!err) {
			try {
				std::unique_lock l{mutex};
				assert(!cid.empty());
				auto it = channels.find(cid);
				if(it != channels.end()) {
					it->second->init(cid, net);
					it->second->create_initial_record();
				} else {
					LOG_WARN("no channel found for chat: %", to_hex(cid));
					err = make_error(securepath::errc::invalid_state, "chat room not set");
				}
			} catch(error const& e) {
				LOG_WARN("exception while initialising storage: %", e);
				err = e;
			}
		}
		ccontext.callback.emit<events::on_init>(server_chat_id{ccontext.sid, cid}, err);
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
				, event_dest<sync::events::on_connect>(&impl::on_connect)
				, event_dest<sync::events::on_disconnect>(&impl::on_disconnect)
				, event_dest<sync::events::on_create_storage>(&impl::on_create_storage) );
	}

	channel& create_chat(std::string name, users members) {
		//check we have keys for the members (as otherwise on_create_storage will fail)
		for(auto&& m : members) {
			if(!ccontext.context.public_keys().find(m.user.public_key_id())) {
				LOG_WARN("cannot create chat because one of the member keys is missing [key=%]", m.user.public_key_id());
				throw make_error(crypto::errc::no_such_key, "cannot create chat, member key missing");
			}
		}
		auto cid = net.create_storage();
		auto ret = channels.emplace(cid, std::make_unique<channel>(ccontext, cid));
		ret.first->second->set_data(std::move(name), std::move(members));
		ccontext.channels.add(cid, ccontext.sync_server);
		return *ret.first->second;
	}

	std::future<void> connect() {
		connect_promise = {};
		std::chrono::seconds timeout{ccontext.config.get_default("network.timeout", 10).as_int64()};
		error err = net.connect(ccontext.sync_server.host, ccontext.sync_server.port, timeout);
		if(err) {
			if(make_error_code(network::errc::already_connected) == err.code()) {
				// connected already, just set the value
				connect_promise.set_value();
			} else {
				throw err;
			}
		}
		return connect_promise.get_future();
	}

	mutable std::mutex mutex;

	chat_conn_context ccontext;
	std::promise<void> connect_promise;

	std::map<sync::storage_id, std::unique_ptr<channel>> channels;
	sync::network_connection net;
};

chat_connection::chat_connection(chat_conn_context context)
: impl_(std::make_unique<impl>(context))
{
}

chat_connection::~chat_connection()
{
}

std::future<void> chat_connection::connect() {
	return impl_->connect();
}

void chat_connection::disconnect() {
	impl_->net.close();
}

channel& chat_connection::create_chat(std::string name, users members) {
	std::unique_lock l{impl_->mutex};
	return impl_->create_chat(std::move(name), std::move(members));
}

channel& chat_connection::join(chat_id const& storage) {
	std::unique_lock l{impl_->mutex};
	impl_->ccontext.channels.add(storage, impl_->ccontext.sync_server);
	return impl_->connect_to_storage(storage);
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

server_id chat_connection::id() const {
	return impl_->ccontext.sid;
}

}