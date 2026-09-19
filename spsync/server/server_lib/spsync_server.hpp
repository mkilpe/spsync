#pragma once

#include "data_server.hpp"
#include "storage_server.hpp"
#include <infrastructure/key_server/server_lib/key_server.hpp>

namespace securepath::sync {

struct spsync_server_params
{
	key_server::server_params key_params{};
	storage_server_params storage_params;
	/// the optional data role (record_data.txt RD12)
	data_server_params data_params;
};

class spsync_server : public key_server::server {
public:
	explicit spsync_server(spsync_server_params params);
	spsync_server(network::context& context, spsync_server_params params);
	~spsync_server();

	int run_and_wait();
	void close() override;

	/// the storage server side (tests and tooling)
	storage_server& storages() { return storage_server_; }

	/// the data role; listening only when the parameters enable it
	data_server& data() { return data_server_; }

private:
	bool init() override;
	void check_key();
	void attach_data_role();

private:
	spsync_server_params params_;
	std::optional<network::context> storage_context_store_;
	storage_server storage_server_;
	data_server data_server_;
};

}

