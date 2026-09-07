#include "groupchat.hpp"

#include <flat_map>
#include "channel.hpp"
#include "events.hpp"

#include <spsync/client/contact_handler.hpp>
#include <spsync/client/protocol/contact.hpp>
#include <spsync/client/events.hpp>
#include <spsync/comm/net_connection.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/engine/sync_engine.hpp>
#include <spsync/protocol/ports.hpp>

#include <securepath/common/key_value_database.hpp>
#include <securepath/crypto/key_generation.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/network/encrypted_net_base.hpp>
#include <securepath/network/encryption/error.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

#include <infrastructure/key_client/key_client.hpp>
#include <infrastructure/key_server/server_lib/defaults.hpp>

#include <securepath/serialisation/vector.hpp>

#include <atomic>
#include <filesystem>
#include <set>
#include <thread>

namespace securepath::groupchat {

static database::connection_ptr open_gc_client_database(groupchat_config const& config) {
	return database::sqlite::create_sqlite_connection(config.db());
}

static network::encrypted_net_base_params net_base_params(groupchat_config const& conf) {
	if(!conf.path.empty()) {
		//make sure the path exists, this does nothing if it already does
		std::filesystem::create_directories(conf.path);
	}
	network::encrypted_net_base_params params{conf.db(), conf.db(), conf.db(), conf.db()};
	params.root_public_key_file = conf.root_public_key_file;
	return params;
}

/// connection timeout of the key registration attempts at the replicas (they run in the
/// background on connect and must not hold a shutdown for long)
static constexpr std::chrono::seconds replica_registration_timeout{5};

gc_servers default_servers() {
	return gc_servers{"gc.securepath.fi",
			sync::default_key_server_port,
			sync::default_storage_server_port,
			packet_transport::default_packet_server_port};
}

struct groupchat::impl
: public network::encrypted_net_base
, public event_system::event_handler
{
	impl(event_system::event_handler& callb, network::context* c, groupchat_config conf, sync::util::config& config)
	: encrypted_net_base(network::client_tag, net_base_params(conf))
	, event_handler(callb.event_loop())
	, own_context(c ? std::optional<network::context>{} : construct_context())
	, context(c ? *c : *own_context)
	, conf(std::move(conf))
	, database(open_gc_client_database(this->conf))
	, callback(callb)
	, channels(database)
	, cconn(context, callback, database)
	, config(config)
	{
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
		fallbacks = gc_info->find<std::vector<sync_replica>>("fallbacks").value_or(std::vector<sync_replica>{});
		cconn.set_own_account(info);
	}

	void set_fallbacks(std::vector<sync_replica> replicas) {
		LOG_INFO("groupchat: {} replica(s) of the home server", replicas.size());
		fallbacks = std::move(replicas);
		gc_info->insert("fallbacks", fallbacks);
	}

	/**
	 * Make sure the replica's key server knows our key (plan 4.5): a replica verifies the
	 * records we commit against its own key store. Returns true when the key is there.
	 */
	bool try_register_key_at(host_port const& key_server) {
		bool ok = false;
		try {
			key_client::client client(context);
			client.connect(key_server.host, key_server.port, replica_registration_timeout);
			client.wait_for_connection();
			auto my_key = my_private_key(context.private_data());
			if(!client.find_key(my_key.id())) {
				client.register_key(my_key.public_key());
			}
			ok = true;
			LOG_INFO("own key registered at key server {}", key_server);
		} catch(std::exception const& ex) {
			LOG_WARN("could not register own key at key server {}: {}", key_server, ex.what());
		}
		return ok;
	}

	std::vector<host_port> unregistered_replica_key_servers() {
		std::unique_lock l{registration_mutex};
		std::vector<host_port> ret;
		for(auto const& r : fallbacks) {
			if(!registered_key_servers.contains(r.key_server)) {
				ret.push_back(r.key_server);
			}
		}
		return ret;
	}

	void register_key_at_replicas() {
		for(auto const& ks : unregistered_replica_key_servers()) {
			if(try_register_key_at(ks)) {
				std::unique_lock l{registration_mutex};
				registered_key_servers.insert(ks);
			}
		}
	}

	/// the registration attempts block for their timeouts, so connect() runs them aside
	void start_background_registration() {
		if(!unregistered_replica_key_servers().empty() && !registration_running.exchange(true)) {
			if(registration_thread.joinable()) {
				registration_thread.join();
			}
			registration_thread = std::jthread([this] {
					register_key_at_replicas();
					registration_running = false;
				});
		}
	}

	bool init_crypto() {
		bool ret = !context.private_data().my_private_key();
		if(ret) {
			create_crypto_materials();
		}
		return ret;
	}

	void create_crypto_materials() {
		context.private_data().set_my_private_key(crypto::generate_private_key());
	}

	void create_account(gc_servers const& server, std::string const& name) {
		LOG_TRACE("groupchat create_account [server={}:{{{}:{}:{}}}]", server.host, server.key_server_port, server.sync_server_port, server.packet_server_port);

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
		set_fallbacks(server.fallbacks);

		set_config();
		// the replicas learn the key now when they are reachable, connect() retries the rest
		register_key_at_replicas();
	}

	void set_config() {
		config.set_database(database, "config");
		// set config values so that they can be found via json interface and such
		if(!config.find("network.timeout")) {
			config.set("network.timeout", default_timeout);
		}
	}

	void on_create(server_chat_id id, sync::users us, error err) {
		if(!err) {
			for(auto&& c : us) {
				if(c.user != info.me.id()) {
					//t: read the host_port from contact data
					send_chat_invitation(user{c.user, host_port{}}, "", id.cid);
				}
			}
		}
		callback.emit<events::on_create>(id, us, err);
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
				, event_dest<events::on_create>(&impl::on_create)
				, event_forward(callback) );

	}

	void register_my_key(host_port const& server) {
		//t: non-blocking
		std::chrono::seconds timeout{config.get_default("network.timeout", default_timeout).as_int64()};
		key_client::client client(context);
		client.connect(server.host, server.port, timeout);
		client.wait_for_connection();
		auto my_key = context.private_data().my_private_key();
		assert(my_key);
		client.register_key(my_key->public_key());
	}

	std::shared_ptr<chat_connection> create_connection(host_port const& hp) {
		auto id = ++last_id;
		// the home server comes with the account's key server and its replicas (plan 4.5),
		// a foreign server (a chat we were invited to) is assumed to bundle a default key server
		bool const home = hp == info.server;
		host_port key_server = home ? info.me.key_server() : host_port{hp.host, sync::default_key_server_port};
		auto p = std::make_shared<chat_connection>(chat_conn_context{id, key_server, hp, *this, context, channels,
			config, conf.path, home ? sync_endpoints(fallbacks) : std::vector<host_port>{}});
		hp_map[hp] = id;
		connections[id] = p;
		return p;
	}

	void send_chat_invitation(user receiver, std::string message, chat_id const& cid) {
		auto hp = channels.find_server(cid);
		if(!hp) {
			LOG_TRACE("no chat with id {}", to_hex(cid));
			throw make_error(errc::no_such_data, "could not find chat");
		}

		std::shared_ptr<chat_connection> conn;
		auto it = hp_map.find(*hp);
		if(it != hp_map.end()) {
			auto c_it = connections.find(it->second);
			if(c_it != connections.end()) {
				conn = c_it->second;
			}
		}
		if(!conn) {
			LOG_TRACE("no connection fot chat with id {}", to_hex(cid));
			throw make_error(errc::no_such_data, "could not find connection for chat");
		}
		auto& channel = conn->get(cid);
		cconn.send_storage_invitation(std::move(receiver), channel.name(), std::move(message), channel.storage_info());
	}

	gc::account_info info;
	/// replicas of the home sync server (plan 4.5), persisted in gc_info
	std::vector<sync_replica> fallbacks;
	std::optional<network::context> own_context;
	network::context& context;
	groupchat_config const conf;

	database::connection_ptr database;
	std::unique_ptr<key_value_database> gc_info;
	event_system::event_handler& callback;

	server_id last_id{};
	std::flat_map<host_port, server_id> hp_map;

	channel_list channels;
	std::flat_map<server_id, std::shared_ptr<chat_connection>> connections;

	sync::client::contact_handler cconn;
	sync::util::config& config;

	/// key servers of the replicas that hold our key already (this process' knowledge)
	std::mutex registration_mutex;
	std::set<host_port> registered_key_servers;
	std::atomic<bool> registration_running{};
	std::jthread registration_thread;
};

bool groupchat::check_account_exists(groupchat_config const& conf) const {
	try {
		auto db = open_gc_client_database(conf);
		return db && db->has_table("gc_info");
	} catch(std::exception const& ex) {
		LOG_WARN("failed to open database: {}", conf.db());
	}
	return false;
}

groupchat::groupchat(event_system::event_handler& callback, groupchat_config conf)
: gc_config_(std::move(conf))
, callback_(callback)
, impl_(check_account_exists(gc_config_) ? std::make_unique<impl>(callback_, nullptr, gc_config_, config_) : nullptr)
{
	if(impl_) {
		impl_->load_info();
	}
}

groupchat::groupchat(event_system::event_handler& callback, network::context& context, groupchat_config conf)
: gc_config_(std::move(conf))
, callback_(callback)
, context_(&context)
, impl_(check_account_exists(gc_config_) ? std::make_unique<impl>(callback_, &context, gc_config_, config_) : nullptr)
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
	std::chrono::seconds timeout{impl_->config.get_default("network.timeout", default_timeout).as_int64()};
	error err = impl_->cconn.connect(impl_->info.packet_server, timeout);
	if(err) {
		if(make_error_code(network::errc::already_connected) == err.code()) {
			// connected already, emit event nevertheless
			impl_->callback.emit<sync::client::events::on_connect>();
		}
	}
	if(impl_->connections.empty()) {
		load_channels();
	}
	impl_->start_background_registration();
	for(auto&& v : impl_->connections) {
		v.second->connect();
	}
}

std::vector<sync_replica> groupchat::fallback_servers() const {
	return impl_ ? impl_->fallbacks : std::vector<sync_replica>{};
}

void groupchat::set_fallback_servers(std::vector<sync_replica> replicas) {
	assert(impl_);
	impl_->set_fallbacks(std::move(replicas));
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
		impl_ = std::make_unique<impl>(callback_, context_, gc_config_, config_);
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
	host_port s = hp;
	if(!s.is_valid()) {
		s = impl_->info.server;
	}
	std::shared_ptr<chat_connection> ret;
	auto it = impl_->hp_map.find(s);
	if(it != impl_->hp_map.end()) {
		auto c_it = impl_->connections.find(it->second);
		if(c_it != impl_->connections.end()) {
			ret = c_it->second;
		}
	}
	if(!ret) {
		ret = impl_->create_connection(s);
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

void groupchat::send_chat_invitation(user receiver, std::string message, chat_id const& cid) {
	assert(impl_);
	impl_->send_chat_invitation(receiver, message, cid);
}

channel_info groupchat::join_chat(sync::client::request_id id) {
	auto r = requests().find(id);
	if(!r || r->tag != sync::client::invite_tag) {
		throw make_error(securepath::errc::no_such_data, "no such chat invitation");
	}

	auto data = serialisation::asn_der_deserialise<sync::client::protocol::invitation_data>(r->data);

	auto conn = load(data.sync_server);
	conn->join(data.to_storage_info(), data.name);

	requests().remove(id);
	return channel_info{data.sid, data.name};
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

sync::util::config& groupchat::config() {
	return config_;
}

}
