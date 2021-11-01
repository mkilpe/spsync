#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/contact_connection.hpp>
#include <spsync/client/events.hpp>

#include <spsync/test/util.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/test/test_progress.hpp>
#include <spsync/test/test_server_runner.hpp>

namespace securepath::sync::client::test {

namespace {
class test_client : public event_system::event_handler {
public:
	test_client(event_system::event_loop& loop, network::context& context, std::string const& dbname)
	: event_handler(loop)
	, conn(context, *this, sync::test::create_test_database(dbname))
	{
		conn.set_own_id(user{my_private_key(context.private_data()).id()
			, host_port{"127.0.0.1", packet_transport::default_packet_server_port}});
	}

	~test_client() {
		event_handler::stop_handler();
	}

	void connect() {
		conn.connect(host_port{"127.0.0.1", packet_transport::default_packet_server_port});
	}

	void disconnect() {
		conn.close();
	}

	void on_connect() {
		LOG_TRACE("on_connect");
		try {
			connected.set_value();
		} catch(...) {}
	}

	void on_disconnect(error err) {
		LOG_TRACE("on_disconnect [err=%]", err);
		try {
			connected.set_exception(std::make_exception_ptr(err));
		} catch(...) {}
	}

	void on_contacting(crypto::public_key_id sender, std::string tag, octet_vector data) {

	}

	void on_invitation() {}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<events::on_connect>(&test_client::on_connect)
				, event_dest<events::on_disconnect>(&test_client::on_disconnect)
				, event_dest<events::on_contacting>(&test_client::on_contacting)
				, event_dest<events::on_invitation>(&test_client::on_invitation) );
	}

	void wait_for_connect() {
		auto f = connected.get_future();
		REQUIRE(f.wait_for(2s) == std::future_status::ready);
   		connected = std::promise<void>{};
	}

public:
	contact_connection conn;
	std::promise<void> connected;
};

}

TEST_CASE("contact_connection test", "[unit]") {
	event_system::single_thread_event_loop single_thread_event_loop;
	sync::test::test_context net_context;

	net_context.add_client(2);
	net_context.add_client_keys_for_server();

	packet_transport::packet_server server(net_context.server_context());
	server.run();
	std::this_thread::sleep_for(1s);

	test_client c1(single_thread_event_loop, net_context.client_context(0), "cc_test_c1.db");
	test_client c2(single_thread_event_loop, net_context.client_context(1), "cc_test_c2.db");

	c1.connect();
	c2.connect();

	c1.wait_for_connect();
	c2.wait_for_connect();
}

}