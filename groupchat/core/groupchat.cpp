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
		init_crypto();
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
		run();
		init_crypto();
	}

	void init_crypto() {
		if(!context.private_data().my_private_key()) {
			create_crypto_materials();
		}
	}

	void create_crypto_materials() {
		context.private_data().set_my_private_key(crypto::generate_rsa_private_key(2048));
	}

	void connect_to_storage(sync::storage_id const& sid) {
		assert(!sid.empty());
		channels.emplace(sid, std::make_unique<channel>(parent, context, event_loop(), net, sid));
	}

	void on_connect() {
		parent.on_connect(1);
	}

	void on_disconnect(error const& err) {
		parent.on_disconnect(1, err);
	}

	void on_create_storage(sync::storage_id const& sid, error const& err) {
		if(!err) {
			assert(!sid.empty());
			auto ret = channels.emplace(sid, std::make_unique<channel>(parent, context, event_loop(), net, sid));
			ret.first->second->create_initial_record();
		}
		parent.on_create(1, sid, err);
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
				, event_dest<sync::events::on_connect>(&impl::on_connect)
				, event_dest<sync::events::on_disconnect>(&impl::on_disconnect)
				, event_dest<sync::events::on_create_storage>(&impl::on_create_storage) );
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
	// t: support connections to multiple servers at the same time
	impl_->net.connect(server, port);
	return 1;
}

void groupchat::disconnect(server_id) {

}

sync::storage_id groupchat::create_chat(server_id) {
	return impl_->net.create_storage();
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

}