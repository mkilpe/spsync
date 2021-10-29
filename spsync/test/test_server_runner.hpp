#pragma once

#include <spsync/server/server_lib/spsync_server.hpp>
#include <infrastructure/packet_transport/server/server_lib/packet_server.hpp>

#include <future>

namespace securepath::sync::test {

class test_server
{
public:
	test_server(network::context& context)
	: server_(context, params_)
	, packet_params_{.packet_db=":memory"}
	, packet_server_(context)
	{
	}

	~test_server() {
		stop();
	}

	void run() {
		server_future_ = std::async(std::launch::async, [&]
			{
				try {
					packet_server_.run();
					server_.run_and_wait();
				} catch(...) {
					std::terminate();
				}
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
	packet_transport::packet_server_params packet_params_;
	packet_transport::packet_server packet_server_;
	std::future<void> server_future_;
};

}
