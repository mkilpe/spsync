#include "spsync_server.hpp"

#include <securepath/network/encryption/handshake/pk_handshake.hpp>

namespace securepath::sync {

spsync_server::spsync_server(spsync_server_params params)
: unknown_user_key_server(params.key_params)
, params_(std::move(params))
, storage_context_store_(construct_context())
, storage_server_(*storage_context_store_, params_.storage_params)
{
	storage_context_store_->add_handshake(network::handshake_tag::public_key, [&](network::handshake_data const&){
			return construct_server_pk_handshake(*storage_context_store_);
		});
}

spsync_server::spsync_server(network::context& context, spsync_server_params params)
: unknown_user_key_server(context, params.key_params)
, params_(std::move(params))
, storage_server_(context, params_.storage_params)
{
}

spsync_server::~spsync_server() {
	close();
}

bool spsync_server::init() {
	unknown_user_key_server::init();
	check_key();
	return true;
}

int spsync_server::run_and_wait() {
	LOG_INFO("Starting spsync server (%, %)", params_.key_params.create_endpoint(), params_.storage_params.create_endpoint());
	int ret = unknown_user_key_server::run();
	if(!ret) {
		storage_server_.start();
		unknown_user_key_server::wait();
	}
	return ret;
}

void spsync_server::close() {
	LOG_TRACE("closing spsync server");
	storage_server_.close();
	unknown_user_key_server::close();
}

void spsync_server::check_key() {
	LOG_INFO("checking private key and certificate chain...");
	auto my_key = private_data().my_private_key();
	if(!my_key) {
		throw make_error(securepath::errc::invalid_state, "no private key found for the server");
	}
	auto chain = crypto::create_certificate_chain(my_key->public_key(), keys(), certs());
	if(!chain) {
		throw make_error(securepath::errc::invalid_state, "no certificate chain found for the server");
	}
	LOG_INFO("found certificate chain: %", *chain);
	auto my_chain = private_data().my_certificate_chain();
	if(!my_chain) {
		throw make_error(securepath::errc::invalid_state, "no certificate chain set for the server");
	}
	LOG_INFO("own certificate chain set to %", *my_chain);
}

}