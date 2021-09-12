#include "chat_connection.hpp"
#include "channel.hpp"
#include "events.hpp"

#include <spsync/comm/net_connection.hpp>

#include <securepath/event_system/event_handler.hpp>
#include <securepath/network/encrypted_net_base.hpp>
#include <securepath/network/encryption/handshake/dh_handshake.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

namespace securepath::groupchat {

struct chat_connection::impl
: public network::encrypted_net_base
, public event_system::event_handler
{
	impl(server_id sid, host_port hp, event_system::event_handler& callback, network::context& context)
	: encrypted_net_base(context)
	, event_handler(callback.event_loop())
	, context(context)
	, callback(callback)
	, net(context, *this)
	, sid(sid)
	, hp(std::move(hp))
	{
	}

	~impl() {
		stop_handler();
	}

	channel& connect_to_storage(sync::storage_id const& cid) {
		assert(!cid.empty());
		auto ret = channels.emplace(cid, std::make_unique<channel>(sid, callback, context, cid));
		ret.first->second->init(cid, net);
		return *ret.first->second;
	}

	void on_connect() {
		callback.emit<events::on_connect>(sid);
	}

	void on_disconnect(error const& err) {
		callback.emit<events::on_disconnect>(sid, err);
	}

	void on_create_storage(sync::storage_id const& cid, error err) {
		if(!err) {
			assert(!cid.empty());
			auto it = channels.find(cid);
			if(it != channels.end()) {
				it->second->init(cid, net);
				it->second->create_initial_record();
			} else {
				LOG_WARN("no channel found for chat: %", to_hex(cid));
				err = make_error(securepath::errc::invalid_state, "chat room not set");
			}
		}
		callback.emit<events::on_create>(sid, cid, err);
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
				, event_dest<sync::events::on_connect>(&impl::on_connect)
				, event_dest<sync::events::on_disconnect>(&impl::on_disconnect)
				, event_dest<sync::events::on_create_storage>(&impl::on_create_storage) );
	}

	channel& create_chat(std::string name) {
		auto cid = net.create_storage();
		auto ret = channels.emplace(cid, std::make_unique<channel>(sid, callback, context, cid));
		ret.first->second->set_name(std::move(name));
		return *ret.first->second;
	}

	void connect() {
		net.connect(hp.host, hp.port);
	}

	network::context& context;
	event_system::event_handler& callback;
	sync::network_connection net;

	std::map<sync::storage_id, std::unique_ptr<channel>> channels;

	server_id const sid;
	host_port const hp;
};

chat_connection::chat_connection(server_id sid, host_port hp, event_system::event_handler& callback, network::context& context)
: impl_(std::make_unique<impl>(sid, hp, callback, context))
{
}

chat_connection::~chat_connection()
{
}

void chat_connection::connect() {
	return impl_->connect();
}

void chat_connection::disconnect() {
	impl_->net.close();
}

channel& chat_connection::create_chat(std::string name) {
	return impl_->create_chat(std::move(name));
}

channel& chat_connection::join(chat_id const& storage) {
	return impl_->connect_to_storage(storage);
}

channel& chat_connection::get(chat_id const& storage) {
	auto it = impl_->channels.find(storage);
	if(it == impl_->channels.end()) {
		throw std::runtime_error("no such storage");
	}
	return *it->second;
}

network::context& chat_connection::context() {
	return impl_->context;
}

host_port chat_connection::end_point() const {
	return impl_->hp;
}

}