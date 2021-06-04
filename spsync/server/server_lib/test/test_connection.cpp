
#include <spsync/server/server_lib/spsync_server.hpp>
#include <spsync/comm/net_connection.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/engine/sync_engine.hpp>
#include <spsync/test/util.hpp>
#include <spsync/test/test_progress.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/event_system/event_handler.hpp>
#include <securepath/network/test/support/testing_context.hpp>
#include <infrastructure/key_client_lib/unknown_user_key_client.hpp>
#include <infrastructure/key_server/server_lib/defaults.hpp>

#include <future>

// + (1)

namespace securepath::sync {
namespace {
class test_server
{
public:
	test_server(network::context& context)
	: server_(context, params_)
	{
	}

	~test_server() {
		stop();
	}

	void run() {
		server_future_ = std::async(std::launch::async, [&]
			{
				server_.run_and_wait();
			});
	}

	void stop() {
		server_.close();
		if(server_future_.valid()) {
			try {
				server_future_.wait();
			} catch(...)
			{} // ignore
		}
	}

private:
	spsync_server_params params_;
	spsync_server server_;
	std::future<void> server_future_;
};

class test_client : public event_system::event_handler {
public:
	test_client(network::context& context, event_system::event_loop& eloop)
	: event_handler(eloop)
	, net(context, *this)
	{
	}

	void connect() {
		net.connect("127.0.0.1", default_storage_server_port);
	}

	void create_remote_storage() {
		net.create_storage();
	}

	void connect_to_storage(storage_id const& sid) {
		assert(!sid.empty());

		storage_connection sconn{net.create_storage_connection(sid)};
		engine = std::make_unique<sync_engine>(event_loop(), sconn.input(), enc_keys, engine_config);

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

	network_connection net;

	database::connection_ptr database{test::create_test_database()};
	test::test_progress progress;
	record_storage storage{database};
	encryption_key_storage enc_keys{database};
	sync_engine_config engine_config;

	std::unique_ptr<sync_engine> engine;

private:
	std::promise<void> connected_;
	std::promise<void> storage_created_;
};

}

TEST_CASE("connection test", "[system]") {
	event_system::event_loop event_loop;
	network::test::testing_context net_context;
	net_context.set_server_dh_parameters();
	net_context.set_server_pk_parameters();
	net_context.set_client_dh_parameters();
	net_context.set_client_pk_parameters();

	//add client key to the db
//	net_context.keys.insert(my_private_key(net_context.client_private_data).public_key());

	test_server server(net_context.server_context);
	server.run();
	std::this_thread::sleep_for(1s);

	key_client::unknown_user_key_client key_client(net_context.client_context);
	key_client.connect("127.0.0.1", key_server::default_unknown_user_key_server_port);
	key_client.wait_for_connection();
	key_client.register_key(net_context.client_private_data.my_private_key()->public_key());

	test_client client(net_context.client_context, event_loop);
	LOG_TRACE("AAA1");
	client.connect();
	LOG_TRACE("AAA2");
	client.wait_for_connection();
	LOG_TRACE("AAA3");
	client.create_remote_storage();
	LOG_TRACE("AAA4");
	client.wait_for_storage_created();
}

}
