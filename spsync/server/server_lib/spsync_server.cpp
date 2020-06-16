#include "spsync_server.hpp"

#include <securepath/network/encryption/handshake/pk_handshake.hpp>

namespace securepath::sync {

spsync_server::spsync_server(spsync_server_params params)
: params_(std::move(params))
, storage_context_(key_server_.construct_context())
, storage_server_(storage_context_)
{
	storage_context_.add_handshake(network::handshake_tag::public_key, [&](network::handshake_data const&){
			return construct_server_pk_handshake(storage_context_);
		});
}

int spsync_server::run_and_wait() {
	return 0;
}

}