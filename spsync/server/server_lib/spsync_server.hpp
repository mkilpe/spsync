#pragma once

#include "storage_server.hpp"
#include <infrastructure/key_server/server_lib/key_server.hpp>

namespace securepath::sync {

struct spsync_server_params
{
	key_server::server_params key_params{};
	storage_server_params storage_params;
};

class spsync_server : public key_server::server {
public:
	explicit spsync_server(spsync_server_params params);
	spsync_server(network::context& context, spsync_server_params params);
	~spsync_server();

	int run_and_wait();
	void close() override;

private:
	bool init() override;
	void check_key();

private:
	spsync_server_params params_;
	std::optional<network::context> storage_context_store_;
	storage_server storage_server_;
};

}

