
#include <spsync/server/server_lib/spsync_server.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>
#include <securepath/database/sqlite/connection.hpp>

#include <future>

// + (1)

namespace securepath::sync {
namespace {
class test_server
{
public:
	test_server()
	: server_(params_)
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
}

TEST_CASE("connection test", "[system]") {
	test_server server;
}

}
