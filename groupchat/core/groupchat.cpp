#include "groupchat.hpp"
#include "channel.hpp"

#include <spsync/comm/net_connection.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/engine/sync_engine.hpp>

#include <securepath/crypto/rsa.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/network/encrypted_net_base.hpp>
#include <securepath/network/encryption/handshake/dh_handshake.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

#include <infrastructure/key_client_lib/unknown_user_key_client.hpp>
#include <infrastructure/key_server/server_lib/defaults.hpp>

namespace securepath::groupchat {

static database::connection_ptr open_gc_client_database(groupchat_config config) {
	return database::sqlite::create_sqlite_connection(config.db);
}

struct groupchat::impl
: public network::encrypted_net_base
, public event_system::event_handler
{
	impl(groupchat& parent, network::context& context, event_system::event_loop& eloop, groupchat_config conf)
	: parent(parent)
	, encrypted_net_base(network::client_tag, {conf.db, conf.db, conf.db, conf.db})
	, event_handler(eloop)
	, context(context)
	, conf(std::move(conf))
	, net(context, *this)
	, database(open_gc_client_database(conf))
	{
		network::enable_client_dh_handshake(context);
		network::enable_client_pk_handshake(context);
	}

	impl(groupchat& parent, event_system::event_loop& eloop, groupchat_config conf)
	: parent(parent)
	, encrypted_net_base(network::client_tag, {conf.db, conf.db, conf.db, conf.db})
	, event_handler(eloop)
	, own_context(construct_context())
	, context(*own_context)
	, conf(std::move(conf))
	, net(context, *this)
	, database(open_gc_client_database(conf))
	{
		network::enable_client_dh_handshake(context);
		network::enable_client_pk_handshake(context);
		run();
	}

	bool init_crypto() {
		bool ret = !context.private_data().my_private_key();
		if(ret) {
			create_crypto_materials();
		}
		return ret;
	}

	void create_crypto_materials() {
		context.private_data().set_my_private_key(crypto::generate_rsa_private_key(2048));
	}

	void connect_to_storage(sync::storage_id const& sid) {
		assert(!sid.empty());
		auto ret = channels.emplace(sid, std::make_unique<channel>(parent, context, event_loop(), sid));
		ret.first->second->init(net);
	}

	void on_connect() {
		parent.on_connect(1);
	}

	void on_disconnect(error const& err) {
		LOG_TRACE("disconnected");
		parent.on_disconnect(1, err);
	}

	void on_create_storage(sync::storage_id const& sid, error err) {
		if(!err) {
			assert(!sid.empty());
			auto it = channels.find(sid);
			if(it != channels.end()) {
				it->second->init(net);
				it->second->create_initial_record();
			} else {
				err = make_error(securepath::errc::invalid_state, "chat room not set");
			}
		}
		parent.on_create(1, sid, err);
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
				, event_dest<sync::events::on_connect>(&impl::on_connect)
				, event_dest<sync::events::on_disconnect>(&impl::on_disconnect)
				, event_dest<sync::events::on_create_storage>(&impl::on_create_storage) );
	}

	sync::storage_id create_chat(server_id, std::wstring name) {
		auto sid = net.create_storage();
		auto ret = channels.emplace(sid, std::make_unique<channel>(parent, context, event_loop(), sid));
		ret.first->second->set_name(std::move(name));
		return sid;
	}

	void register_my_key(std::string_view server) {
		//t: non-blocking
		key_client::unknown_user_key_client client(context);
		client.connect(server, key_server::default_unknown_user_key_server_port);
		client.wait_for_connection();
		auto my_key = context.private_data().my_private_key();
		assert(my_key);
		client.register_key(my_key->public_key());
	}

	server_id connect(std::string_view server, std::uint16_t port) {
		if(init_crypto()) {
			register_my_key(server);
		}
		// t: support connections to multiple servers at the same time
		net.connect(server, port);
		return 1;
	}

	groupchat& parent;
	std::optional<network::context> own_context;
	network::context& context;
	groupchat_config conf;

	sync::network_connection net;
	database::connection_ptr database;

	std::map<sync::storage_id, std::unique_ptr<channel>> channels;
};

groupchat::groupchat(groupchat_config conf, event_system::event_loop& loop)
: impl_(std::make_unique<impl>(*this, loop, std::move(conf)))
{
}

groupchat::groupchat(network::context& context, groupchat_config conf, event_system::event_loop& loop)
: impl_(std::make_unique<impl>(*this, context, loop, std::move(conf)))
{
}

groupchat::~groupchat()
{
}


server_id groupchat::connect(std::string_view server, std::uint16_t port) {
	return impl_->connect(server, port);
}

void groupchat::disconnect(server_id) {
	impl_->net.close();
}

sync::storage_id groupchat::create_chat(server_id sid, std::wstring name) {
	return impl_->create_chat(sid, std::move(name));
}

void groupchat::change_user(server_id const&, chat_id const& storage, sync::users change) {
	auto it = impl_->channels.find(storage);
	if(it == impl_->channels.end()) {
		throw std::runtime_error("no such storage");
	}
	return it->second->change_user(std::move(change));
}

void groupchat::join(server_id const& server, chat_id const& storage) {

}

message_id groupchat::send_message(server_id const&, chat_id const& storage, std::string const& message) {
	auto it = impl_->channels.find(storage);
	if(it == impl_->channels.end()) {
		throw std::runtime_error("no such storage");
	}
	return it->second->send_message(message);
}

network::context& groupchat::context() {
	return impl_->context;
}

}