#pragma once

#include "peer_config.hpp"

#include <securepath/network/encryption/context.hpp>
#include <spsync/protocol/ports.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

using namespace std::chrono_literals;

namespace securepath::sync {

struct storage_server_params {
	std::uint16_t storage_server_port{default_storage_server_port};

	/// this will override the above port if set
	std::optional<asio::ip::tcp::endpoint> storage_server_endpoint;

	asio::ip::tcp::endpoint create_endpoint() const;

	/// connecting/handshake timeout
	std::chrono::seconds timeout{10s};

	/**
	 * Expected public key id (hex) of this server's signing key (plan 3.3); empty derives
	 * the identity from the key. Startup fails when set and not matching the actual key.
	 */
	std::string server_id;

	/// the known replication peers of this server (plan 3.3); an own entry is dropped on
	/// resolve so one shared cluster configuration can be used
	std::vector<peer_config> peers;
};

class storage_server {
public:
	storage_server(network::context&, storage_server_params = {});
	~storage_server();

	void start();
	void close();

	/// the resolved server identity (plan 3.3); empty before start()
	server_identity identity() const;
private:
	class impl;
	// encrypted_server requires this to be shared_ptr
	std::shared_ptr<impl> impl_;
};

}

