#pragma once

#include <spsync/server/server_lib/spsync_server.hpp>
#include <infrastructure/packet_transport/server/server_lib/packet_server.hpp>

#include <future>

namespace securepath::sync::test {

class test_server
{
public:
	test_server(network::context& context, spsync_server_params params = {})
	: server_(context, params)
	, packet_params_{.packet_db=":memory"}
	, packet_server_(context, packet_params_)
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

	/// the storage server side
	storage_server& storages() { return server_.storages(); }

	/// the data role; listening when the parameters enable it
	data_server& data() { return server_.data(); }

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
	spsync_server server_;
	packet_transport::packet_server_params packet_params_;
	packet_transport::packet_server packet_server_;
	std::future<void> server_future_;
};

}
