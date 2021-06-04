#include "spsync_server.hpp"

#include <securepath/network/encryption/handshake/pk_handshake.hpp>

namespace securepath::sync {

spsync_server::spsync_server(spsync_server_params params)
: params_(std::move(params))
, key_server_(params_.key_params)
, storage_context_store_(key_server_.construct_context())
, storage_server_(*storage_context_store_, params_.storage_params)
{
	storage_context_store_->add_handshake(network::handshake_tag::public_key, [&](network::handshake_data const&){
			return construct_server_pk_handshake(*storage_context_store_);
		});
}

spsync_server::spsync_server(network::context& context, spsync_server_params params)
: params_(std::move(params))
, key_server_(context, params_.key_params)
, storage_server_(context, params_.storage_params)
{
}

spsync_server::~spsync_server() {
	close();
}

int spsync_server::run_and_wait() {
	LOG_INFO("Starting spsync server (%, %)", params_.key_params.create_endpoint(), params_.storage_params.create_endpoint());
	storage_server_.start();
	LOG_INFO("starting key server next...");
	return key_server_.run_and_wait();
}

void spsync_server::close() {
	storage_server_.close();
	key_server_.close();
}

}