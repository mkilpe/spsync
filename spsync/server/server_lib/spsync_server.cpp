// SPDX-License-Identifier: MIT

#include "spsync_server.hpp"
#include <spsync/util/format.hpp>

#include <asio/ip/tcp.hpp>

SPSYNC_FORMAT_VIA_OSTREAM(asio::ip::tcp::endpoint)


#include <securepath/server_common/key_check.hpp>
#include <securepath/network/encryption/handshake/pk_handshake.hpp>

namespace securepath::sync {

spsync_server::spsync_server(spsync_server_params params)
: key_server::server(params.key_params)
, params_(std::move(params))
, storage_context_store_(construct_context())
, storage_server_(*storage_context_store_, params_.storage_params)
, data_server_(*storage_context_store_, params_.data_params)
{
	// role dispatched: the same context accepts clients/peers and dials out to peers (plan 4.1)
	network::enable_pk_handshake(*storage_context_store_);
	attach_data_role();
}

spsync_server::spsync_server(network::context& context, spsync_server_params params)
: key_server::server(context, params.key_params)
, params_(std::move(params))
, storage_server_(context, params_.storage_params)
, data_server_(context, params_.data_params)
{
	attach_data_role();
}

spsync_server::~spsync_server() {
	close();
}

bool spsync_server::init() {
	bool const ok = key_server::server::init();
	if(ok) {
		check_key();
	}
	return ok;
}

int spsync_server::run() {
	LOG_INFO("Starting spsync server ({}, {})", params_.key_params.create_endpoint(), params_.storage_params.create_endpoint());
	int ret = key_server::server::run(4, 2);
	if(!ret) {
		// the data role first: the record role reads what it holds when it starts
		if(params_.data_params.enabled) {
			data_server_.start();
		}
		storage_server_.start();
	}
	return ret;
}

int spsync_server::run_and_wait() {
	int ret = run();
	if(!ret) {
		key_server::server::wait();
	}
	return ret;
}

void spsync_server::close() {
	LOG_TRACE("closing spsync server");
	data_server_.close();
	storage_server_.close();
	key_server::server::close();
}

/// an all-in-one server (record_data.txt RD12): the record role hears what the data role completes
void spsync_server::attach_data_role() {
	if(params_.data_params.enabled) {
		storage_server_.attach_data_role(data_server_);
	}
}

void spsync_server::check_key() {
	server_common::check_server_key(construct_context());
}

}