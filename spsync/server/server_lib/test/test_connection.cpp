
#include <spsync/test/test_server_runner.hpp>

#include <spsync/client/record_util.hpp>
#include <spsync/comm/net_connection.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/engine/sync_engine.hpp>
#include <spsync/test/util.hpp>
#include <spsync/test/test_progress.hpp>
#include <spsync/test/test_context.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <infrastructure/key_client/key_client.hpp>
#include <infrastructure/key_server/server_lib/defaults.hpp>

#include <future>

// + (1) connect single client by registering key first
// + (2) connect two clients, first creates storage, second one joins it
// + (3) connect two clients sharing storage, reconnect test
// + (4) connect many clients to share storage

namespace securepath::sync {
namespace {

class test_client : public event_system::event_handler {
public:
	test_client(network::context& context, event_system::single_thread_event_loop& eloop, int n = 0)
	: event_handler(eloop)
	, context(context)
	, net(context, *this)
	, database(test::create_test_database("test_connection_client_" + std::to_string(n) + ".db"))
	{
		//add_test_key();
	}

	~test_client() {
		stop_handler();
	}

	void connect() {
		net.connect("127.0.0.1", default_storage_server_port);
	}

	void disconnect() {
		net.close();
	}

	storage_id create_remote_storage() {
		return net.create_storage();
	}

	void connect_to_storage(storage_id const& sid) {
		assert(!sid.empty());

		storage_connection sconn{net.create_storage_connection(sid, storage, progress)};
		engine = std::make_unique<sync_engine>(event_loop(), sconn.input(), cc, engine_config);

		//after this the events will be received
		sconn.attach(*engine);
	}

	void wait_for_connection() {
		connected_.get_future().get();
	}

	void on_connect() {
		try {
			connected_.set_value();
		} catch(...) {}
	}

	void on_disconnect(error const& err) {
		try {
			connected_.set_exception(std::make_exception_ptr(err));
		} catch(...) {}
	}

	void on_create_storage(storage_id const& sid, error const& err) {
		if(err) {
			storage_created_.set_exception(std::make_exception_ptr(err));
		} else {
			connect_to_storage(sid);
			storage_created_.set_value();
		}
	}

	void wait_for_storage_created() {
		storage_created_.get_future().get();
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<events::on_connect>(&test_client::on_connect)
				, event_dest<events::on_disconnect>(&test_client::on_disconnect)
				, event_dest<events::on_create_storage>(&test_client::on_create_storage) );
	}

	void create_initial_record(std::vector<crypto::public_key_id> members = {}) {
		// set initial key, use hard coded one for testing
		auto own_key = context.private_data().my_private_key();
		assert(own_key);
		add_test_key();
		users initial;
		initial.add(util::user_access{own_key->id(), util::access_type::user_management_access});
		for(auto v : members) {
			initial.add(util::user_access{v, util::access_type::user_management_access});
		}
		engine->sync_user_change(encrypt_last_key_for_users(initial, cc));
	}

	//t: remove when we have real key handling implemented
	void add_test_key() {
		enc_keys.insert(encryption_key{sequence_number{1}, to_octet_vector("12345678901234567890123456789012")});
	}

	network::context& context;
	network_connection net;

	database::connection_ptr database;
	test::test_progress progress;
	record_storage storage{database};
	encryption_key_storage enc_keys{database};
	crypto_context cc{context.public_keys(), context.private_data(), enc_keys, storage};
	sync_engine_config engine_config;

	std::unique_ptr<sync_engine> engine;

private:
	std::promise<void> connected_;
	std::promise<void> storage_created_;
};

}

// (1) connect single client by registering key first
TEST_CASE("connection test", "[system]") {
	event_system::single_thread_event_loop single_thread_event_loop;
	test::test_context net_context;

	net_context.add_client();

	test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	key_client::client key_client(net_context.client_context(0));
	key_client.connect("127.0.0.1", key_server::default_key_server_port);
	key_client.wait_for_connection();
	key_client.register_key(net_context.client_context(0).private_data().my_private_key()->public_key());

	test_client client(net_context.client_context(0), single_thread_event_loop);
	client.connect();
	client.wait_for_connection();
	client.create_remote_storage();
	client.wait_for_storage_created();
	client.create_initial_record();

	for(int i = 0; i != 5; ++i) {
		client.engine->sync_object_change(util::create_object_id(), metadata{});
	}

	WAIT_CHECK(client.storage.last_block().sequence == sequence_number{6}, 2s);
}

// (2) connect two clients, first creates storage, second one joins it
TEST_CASE("two clients test", "[system]") {
	event_system::single_thread_event_loop single_thread_event_loop;
	test::test_context net_context;

	net_context.add_client(2);
	net_context.add_client_keys_for_server();
	net_context.share_client_keys();

	test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	test_client client1(net_context.client_context(0), single_thread_event_loop, 0);
	client1.connect();
	client1.wait_for_connection();
	auto sid = client1.create_remote_storage();
	client1.wait_for_storage_created();
	client1.create_initial_record({net_context.key_id(1)});

	test_client client2(net_context.client_context(1), single_thread_event_loop, 1);
	client2.connect();
	client2.wait_for_connection();
	client2.connect_to_storage(sid);

	WAIT_CHECK(test::check_commit_records_equal(sequence_number{1}, client1.storage, client2.storage), 2s);

	client2.engine->sync_object_change(util::create_object_id(), metadata{});

	WAIT_CHECK(test::check_commit_records_equal(sequence_number{2}, client1.storage, client2.storage), 2s);
}

// (3) connect two clients sharing storage, reconnect test
TEST_CASE("reconnect test", "[system]") {
	event_system::single_thread_event_loop single_thread_event_loop;
	test::test_context net_context;

	net_context.add_client(2);
	net_context.add_client_keys_for_server();
	net_context.share_client_keys();

	test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	test_client client1(net_context.client_context(0), single_thread_event_loop, 0);
	client1.connect();
	client1.wait_for_connection();
	auto sid = client1.create_remote_storage();
	client1.wait_for_storage_created();
	client1.create_initial_record({net_context.key_id(1)});

	test_client client2(net_context.client_context(1), single_thread_event_loop, 1);
	client2.connect();
	client2.wait_for_connection();
	client2.connect_to_storage(sid);

	WAIT_CHECK(test::check_commit_records_equal(sequence_number{1}, client1.storage, client2.storage), 2s);

	client2.disconnect();
	for(int i = 0; i != 5; ++i) {
		client1.engine->sync_object_change(util::create_object_id(), metadata{});
	}
	WAIT_CHECK(client1.storage.last_block().sequence == sequence_number{6}, 2s);

	client2.connect();
	WAIT_CHECK(test::check_commit_records_equal(sequence_number{6}, client1.storage, client2.storage), 2s);

	client2.disconnect();
	for(int i = 0; i != 5; ++i) {
		client1.engine->sync_object_change(util::create_object_id(), metadata{});
	}
	client2.engine->sync_object_change(util::create_object_id(), metadata{});

	WAIT_CHECK(client1.storage.last_block().sequence == sequence_number{11}, 2s);

	client2.connect();
	WAIT_CHECK(test::check_commit_records_equal(sequence_number{12}, client1.storage, client2.storage), 2s);
}

bool check_commit_records_equal(sequence_number s, std::vector<std::unique_ptr<test_client>> const& c) {
	assert(c.size() > 1);
	bool ret = true;
	for(int i = 0; i != c.size()-1; ++i) {
		ret = ret && test::check_commit_records_equal(s, c[i]->storage, c[i+1]->storage);
	}
	return ret;
}

// (4) connect many clients to share storage
TEST_CASE("multi client test", "[system]") {
	int const client_count = 20;

	event_system::single_thread_event_loop single_thread_event_loop;
	test::test_context net_context;

	net_context.add_client(client_count);
	net_context.add_client_keys_for_server();
	net_context.share_client_keys();

	test::test_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	std::vector<std::unique_ptr<test_client>> clients;
	for(int i = 0; i != client_count; ++i) {
		clients.push_back(std::make_unique<test_client>(net_context.client_context(i), single_thread_event_loop, i));
		clients.back()->connect();
	}
	for(auto&& v : clients) {
		v->wait_for_connection();
	}

	auto sid = clients[0]->create_remote_storage();
	clients[0]->wait_for_storage_created();

	// add initial members, create_initial_record always adds oneself
	std::vector<crypto::public_key_id> members;
	for(int i = 1; i != client_count; ++i) {
		members.push_back(net_context.key_id(i));
	}
	clients[0]->create_initial_record(members);

	for(int i = 1; i != client_count; ++i) {
		clients[i]->connect_to_storage(sid);
	}
	WAIT_CHECK(check_commit_records_equal(sequence_number{1}, clients), 5s);

	for(int i = 0; i != 5; ++i) {
		clients[0]->engine->sync_object_change(util::create_object_id(), metadata{});
	}

	WAIT_CHECK(check_commit_records_equal(sequence_number{6}, clients), 5s);

	for(int i = 1; i != client_count; ++i) {
		for(int c = 0; c != 5; ++c) {
			clients[i]->engine->sync_object_change(util::create_object_id(), metadata{});
		}
	}

	WAIT_CHECK(check_commit_records_equal(sequence_number{101}, clients), 60s);
}

}
