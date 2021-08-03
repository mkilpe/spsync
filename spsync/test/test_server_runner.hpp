#pragma once

#include <spsync/server/server_lib/spsync_server.hpp>

#include <future>

namespace securepath::sync::test {

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

}
