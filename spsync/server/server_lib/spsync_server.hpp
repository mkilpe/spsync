#ifndef SPSYNC_SERVER_SPSYNC_SERVER_HEADER
#define SPSYNC_SERVER_SPSYNC_SERVER_HEADER

#include "storage_server.hpp"
#include <infrastructure/key_server/server_lib/unknown_user_key_server.hpp>

namespace securepath::sync {

struct spsync_server_params
{
	key_server::unknown_user_key_server_params key_params{.port=key_server::default_unknown_user_key_server_port};
	storage_server_params storage_params;
};

class spsync_server {
public:
	explicit spsync_server(spsync_server_params params);
	spsync_server(network::context& context, spsync_server_params params);
	~spsync_server();

	int run_and_wait();
	void close();

private:
	spsync_server_params params_;
	key_server::unknown_user_key_server key_server_;
	std::optional<network::context> storage_context_store_;
	storage_server storage_server_;
};

}

#endif
