#include "groupchat.hpp"
#include "channel.hpp"
#include "events.hpp"

#include <spsync/client/contact_handler.hpp>
#include <spsync/client/events.hpp>
#include <spsync/comm/net_connection.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/engine/sync_engine.hpp>
#include <spsync/protocol/ports.hpp>

#include <securepath/common/key_value_database.hpp>
#include <securepath/crypto/rsa.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/network/encrypted_net_base.hpp>
#include <securepath/network/encryption/error.hpp>
#include <securepath/network/encryption/handshake/dh_handshake.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

#include <infrastructure/key_client_lib/unknown_user_key_client.hpp>
#include <infrastructure/key_server/server_lib/defaults.hpp>

#include <filesystem>

namespace securepath::groupchat {

static database::connection_ptr open_gc_client_database(groupchat_config const& config) {
	return database::sqlite::create_sqlite_connection(config.db());
}

static network::encrypted_net_base_params net_base_params(groupchat_config const& conf) {
	if(!conf.path.empty()) {
		//make sure the path exists, this does nothing if it already does
		std::filesystem::create_directories(conf.path);
	}
	return {conf.db(), conf.db(), conf.db(), conf.db()};
}

struct groupchat::impl
: public network::encrypted_net_base
, public event_system::event_handler
{
	impl(event_system::event_handler& callb, network::context* c, groupchat_config conf)
	: encrypted_net_base(network::client_tag, net_base_params(conf))
	, event_handler(callb.event_loop())
	, own_context(c ? std::optional<network::context>{} : construct_context())
	, context(c ? *c : *own_context)
	, conf(std::move(conf))
	, database(open_gc_client_database(this->conf))
	, callback(callb)
	, channels(database)
	, cconn(context, callback, database)
	{
		network::enable_client_dh_handshake(context);
		network::enable_client_pk_handshake(context);

		if(!c) {
			run();
		}
	}

	~impl() {
		stop_handler();

		// swap the connections out and destroy so there is no more events
		decltype(connections) tmp;
		tmp.swap(connections);
	}

	void load_info() {
		gc_info = std::make_unique<key_value_database>(database, "gc_info");
		info.me = gc_info->find<user>("me").value();
		info.name = gc_info->find<std::string>("name").value_or(info.me.id().public_key_id().in_hex());
		info.server = gc_info->find<host_port>("server").value_or(host_port{});
		info.packet_server = gc_info->find<host_port>("packet_server").value_or(host_port{});
		cconn.set_own_account(info);
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

	void create_account(gc_servers const& server, std::string const& name) {
		LOG_TRACE("groupchat create_account [server=%:{%:%:%}]", server.host, server.key_server_port, server.sync_server_port, server.packet_server_port);

		database::transaction t{*database};
		init_crypto();
		register_my_key(server.key_server());

		auto my_key = my_private_key(context.private_data());
		context.public_keys().insert(my_key.public_key());

		gc_info = std::make_unique<key_value_database>(database, "gc_info");
		gc_info->insert("me", user{my_key.id(), server.key_server()});
		gc_info->insert("name", name);
		gc_info->insert("server", server.sync_server());
		gc_info->insert("packet_server", server.packet_server());

		info.me = user{my_key.id(), server.key_server()};
		info.name = name;
		info.server = server.sync_server();
		info.packet_server = server.packet_server();
		cconn.set_own_account(info);
	}

	void on_create(server_id sid, chat_id cid, error err) {

	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
				, event_dest<events::on_create>(&impl::on_create)
				, event_forward(callback) );

	}

	void register_my_key(host_port const& server) {
		//t: non-blocking
		key_client::unknown_user_key_client client(context);
		client.connect(server.host, server.port);
		client.wait_for_connection();
		auto my_key = context.private_data().my_private_key();
		assert(my_key);
		client.register_key(my_key->public_key());
	}

	std::shared_ptr<chat_connection> create_connection(host_port const& hp) {
		auto id = ++last_id;
		auto p = std::make_shared<chat_connection>(chat_conn_context{id, hp, *this, context, channels, conf.path});
		hp_map[hp] = id;
		connections[id] = p;
		return p;
	}

	gc::account_info info;
	std::optional<network::context> own_context;
	network::context& context;
	groupchat_config const conf;

	database::connection_ptr database;
	std::unique_ptr<key_value_database> gc_info;
	event_system::event_handler& callback;

	server_id last_id{};
	std::map<host_port, server_id> hp_map;

	channel_list channels;
	std::map<server_id, std::shared_ptr<chat_connection>> connections;

	sync::client::contact_handler cconn;
};

bool groupchat::check_account_exists(groupchat_config const& conf) const {
	try {
		auto db = open_gc_client_database(conf);
		return db && db->has_table("gc_info");
	} catch(std::exception const& ex) {
		LOG_WARN("failed to open database: %", conf.db());
	}
	return false;
}

groupchat::groupchat(event_system::event_handler& callback, groupchat_config conf)
: config_(std::move(conf))
, callback_(callback)
, impl_(check_account_exists(config_) ? std::make_unique<impl>(callback_, nullptr, config_) : nullptr)
{
	if(impl_) {
		impl_->load_info();
	}
}

groupchat::groupchat(event_system::event_handler& callback, network::context& context, groupchat_config conf)
: config_(std::move(conf))
, callback_(callback)
, context_(&context)
, impl_(check_account_exists(config_) ? std::make_unique<impl>(callback_, &context, config_) : nullptr)
{
	if(impl_) {
		impl_->load_info();
	}
}

groupchat::~groupchat()
{
}

void groupchat::connect() {
	assert(impl_);
	error err = impl_->cconn.connect(impl_->info.packet_server);
	if(err) {
		if(make_error_code(network::errc::already_connected) == err.code()) {
			// connected already, emit event nevertheless
			impl_->callback.emit<sync::client::events::on_connect>();
		}
	}
	if(impl_->connections.empty()) {
		load_channels();
	}
	for(auto&& v : impl_->connections) {
			v.second->connect();
	}
}

void groupchat::disconnect() {
	assert(impl_);
	for(auto&& v : impl_->connections) {
		v.second->disconnect();
	}
	impl_->cconn.close();
}

std::optional<gc::account_info> groupchat::account_info() const {
	return impl_ ? impl_->info : std::optional<gc::account_info>{};
}

void groupchat::create_account(gc_servers const& server, std::string const& name) {
	LOG_TRACE("groupchat::create_account");
	if(impl_) {
		throw make_error(sync::errc::constraint_violation, "account already exists");
	}
	try {
		impl_ = std::make_unique<impl>(callback_, context_, config_);
		impl_->create_account(server, name);
	} catch(...) {
		impl_.reset();
		throw;
	}
}

std::deque<channel_id> groupchat::load_channels() {
	assert(impl_);
	std::deque<channel_id> ret;
	for(auto const& v : impl_->channels.enumerate()) {
		auto s = load(v.server);
		s->load(v.cid);
		ret.push_back(channel_id{s->id(), v.cid});
	}
	return ret;
}

std::shared_ptr<chat_connection> groupchat::load(host_port const& hp) {
	assert(impl_);
	std::shared_ptr<chat_connection> ret;
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
	assert(impl_);
	auto c_it = impl_->connections.find(sid);
	return c_it != impl_->connections.end() ? c_it->second : nullptr;
}

std::vector<std::shared_ptr<chat_connection>> groupchat::connections() const {
	std::vector<std::shared_ptr<chat_connection>> ret;
	assert(impl_);
	for(auto v : impl_->connections) {
		ret.push_back(v.second);
	}
	return ret;
}

sync::client::contact_list& groupchat::contacts() {
	assert(impl_);
	return impl_->cconn.contacts();
}

sync::client::request_storage& groupchat::requests() {
	assert(impl_);
	return impl_->cconn.requests();
}

channel_list& groupchat::channel_ids() {
	assert(impl_);
	return impl_->channels;
}

network::context& groupchat::context() {
	assert(impl_);
	return impl_->context;
}

sync::client::contact_handler& groupchat::request_handler() {
	assert(impl_);
	return impl_->cconn;
}

}
