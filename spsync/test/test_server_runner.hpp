// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/server/server_lib/spsync_server.hpp>
#include <infrastructure/packet_transport/server/server_lib/packet_server.hpp>

#include <stdexcept>

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

	/// start the servers: they listen when this returns, no wait is needed before a connect
	void run() {
		packet_server_.run();
		if(server_.run() != 0) {
			throw std::runtime_error("the test server did not start");
		}
	}

	/// the storage server side
	storage_server& storages() { return server_.storages(); }

	/// the data role; listening when the parameters enable it
	data_server& data() { return server_.data(); }

	void stop() {
		server_.close();
		server_.wait();
	}

private:
	spsync_server server_;
	packet_transport::packet_server_params packet_params_;
	packet_transport::packet_server packet_server_;
};

}
