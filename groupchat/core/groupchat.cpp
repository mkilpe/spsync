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
	impl(event_system::event_handler& callback, network::context& context, groupchat_config conf)
	: encrypted_net_base(network::client_tag, {conf.db, conf.db, conf.db, conf.db})
	, event_handler(callback.event_loop())
	, context(context)
	, conf(std::move(conf))
	, database(open_gc_client_database(conf))
	, callback(callback)
	{
		network::enable_client_dh_handshake(context);
		network::enable_client_pk_handshake(context);
	}

	impl(event_system::event_handler& callback, groupchat_config conf)
	: encrypted_net_base(network::client_tag, {conf.db, conf.db, conf.db, conf.db})
	, event_handler(callback.event_loop())
	, own_context(construct_context())
	, context(*own_context)
	, conf(std::move(conf))
	, database(open_gc_client_database(conf))
	, callback(callback)
	{
		network::enable_client_dh_handshake(context);
		network::enable_client_pk_handshake(context);
		run();
	}

	~impl() {
		stop_handler();
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

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		/*
		this is going to be needed later on when developing communication means between contacts
		dispatch( *ev
				, event_dest<sync::events::on_connect>(&impl::on_connect) );*/
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

	std::shared_ptr<chat_connection> create_connection(host_port const& hp) {
		auto id = ++last_id;
		auto p = std::make_shared<chat_connection>(id, hp, callback, context);
		hp_map[hp] = id;
		connections[id] = p;
		return p;
	}

	std::optional<network::context> own_context;
	network::context& context;
	groupchat_config conf;

	database::connection_ptr database;
	event_system::event_handler& callback;

	server_id last_id{};
	std::map<host_port, server_id> hp_map;
	std::map<server_id, std::shared_ptr<chat_connection>> connections;
};

groupchat::groupchat(event_system::event_handler& callback, groupchat_config conf)
: impl_(std::make_unique<impl>(callback, std::move(conf)))
{
}

groupchat::groupchat(event_system::event_handler& callback, network::context& context, groupchat_config conf)
: impl_(std::make_unique<impl>(callback, context, std::move(conf)))
{
}

groupchat::~groupchat()
{
}

std::shared_ptr<chat_connection> groupchat::load(std::string const& host, std::uint16_t port) {
	std::shared_ptr<chat_connection> ret;
	host_port hp{host, port};
	auto it = impl_->hp_map.find(hp);
	if(it != impl_->hp_map.end()) {
		auto c_it = impl_->connections.find(it->second);
		if(c_it != impl_->connections.end()) {
			ret = c_it->second;
		}
	}
	if(!ret) {
		ret = impl_->create_connection(hp);
	}
	return ret;
}

std::shared_ptr<chat_connection> groupchat::find(server_id sid) const {
	auto c_it = impl_->connections.find(sid);
	return c_it != impl_->connections.end() ? c_it->second : nullptr;
}

network::context& groupchat::context() {
	return impl_->context;
}

}
