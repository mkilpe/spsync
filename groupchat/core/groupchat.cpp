#include "groupchat.hpp"

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

struct print_event {
	typedef void type(std::string);
};

struct groupchat::impl
: public network::encrypted_net_base
, public event_system::event_handler
{
	impl(event_system::single_thread_event_loop& eloop, groupchat_config conf)
	: encrypted_net_base(network::client_tag, {conf.db, conf.db, conf.db, conf.db})
	, event_handler(eloop)
	, context(construct_context())
	, conf(std::move(conf))
	, net(context, *this)
	, database(open_gc_client_database(conf))
	{
		if(!context.private_data().my_private_key()) {
			create_crypto_materials();
		}
	}

	void create_crypto_materials() {
		context.private_data().set_my_private_key(crypto::generate_rsa_private_key(2048));
	}

	void main_loop() {

	}

	void print(std::string msg) {
		emit<print_event>(std::move(msg));
	}

	void on_print(std::string msg) {
	}

	void connect_to_storage(sync::storage_id const& sid) {
		assert(!sid.empty());

		//sync::storage_connection sconn{net.create_storage_connection(sid, storage, progress)};
		//engine = std::make_unique<sync::sync_engine>(single_thread_event_loop(), sconn.input(), enc_keys, engine_config);

		//after this the events will be received
		//sconn.attach(*engine);
	}

	void on_connect() {

	}

	void on_disconnect(error const& err) {

	}

	void on_create_storage(sync::storage_id const& sid, error const& err) {

	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
				, event_dest<print_event>(&impl::on_print)
				, event_dest<sync::events::on_connect>(&impl::on_connect)
				, event_dest<sync::events::on_disconnect>(&impl::on_disconnect)
				, event_dest<sync::events::on_create_storage>(&impl::on_create_storage) );
	}

	network::context context;
	groupchat_config conf;

	sync::network_connection net;
	database::connection_ptr database;
};

groupchat::groupchat(groupchat_config conf)
: impl_(std::make_unique<impl>(loop_, std::move(conf)))
{
}

groupchat::~groupchat()
{
}

message_id groupchat::send_message(std::string const& message) {
	//sync::metadata header;
	//header.insert(groupchat_message_id, message);
	auto msg_id = sync::util::create_object_id();
	//impl_->engine->sync_object_change(msg_id, std::move(header));
	return msg_id;
}

}