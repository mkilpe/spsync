
#include <spsync/server/server_lib/spsync_server.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/network/test/support/testing_context.hpp>
#include <infrastructure/key_client_lib/unknown_user_key_client.hpp>

#include <future>

// + (1)

namespace securepath::sync {
namespace {
class test_server : public network::test::testing_context
{
public:
	test_server()
	: server_(params_)
	{
		set_server_dh_parameters();
		set_server_pk_parameters();
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
}

TEST_CASE("connection test", "[system]") {
	test_server server;

	key_client::unknown_user_key_client key_client(server.client_context);
	key_client.register_key(server.client_private_data.my_private_key()->public_key());
}

}
