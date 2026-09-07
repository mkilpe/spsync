#pragma once

#include "peer_config.hpp"

#include <spsync/core/origin_head.hpp>
#include <spsync/core/sync_mode.hpp>
#include <spsync/protocol/ports.hpp>
#include <spsync/protocol/protocol_base.hpp>

#include <securepath/network/encryption/context.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using namespace std::chrono_literals;

namespace securepath::sync {

class storage;

struct storage_server_params {
	std::uint16_t storage_server_port{default_storage_server_port};

	/// this will override the above port if set
	std::optional<asio::ip::tcp::endpoint> storage_server_endpoint;

	asio::ip::tcp::endpoint create_endpoint() const;

	/// connecting/handshake timeout
	std::chrono::seconds timeout{10s};

	/// root path for the storages of this server
	std::string storage_root{"record-storages"};

	/**
	 * Expected public key id (hex) of this server's signing key (plan 3.3); empty derives
	 * the identity from the key. Startup fails when set and not matching the actual key.
	 */
	std::string server_id;

	/// the known replication peers of this server (plan 3.3); an own entry is dropped on
	/// resolve so one shared cluster configuration can be used
	std::vector<peer_config> peers;

	/// the server-to-server listener port (plan 4.1); used when peers are configured
	std::uint16_t s2s_port{default_s2s_port};

	/// overrides the s2s port when set
	std::optional<asio::ip::tcp::endpoint> s2s_endpoint;

	/// how often the replicated storage heads are re-announced to the peers (plan 4.4);
	/// every announcement makes a behind peer pull what it is missing
	std::chrono::seconds anti_entropy_interval{30s};

	asio::ip::tcp::endpoint create_s2s_endpoint() const;
};

class storage_server {
public:
	storage_server(network::context&, storage_server_params = {});
	~storage_server();

	void start();
	void close();

	/// the resolved server identity (plan 3.3); empty before start()
	server_identity identity() const;

	/// open (or create) a storage directly, e.g. for tooling and tests
	std::shared_ptr<storage> open_storage(protocol::storage_id const&, std::optional<storage_modes> = {});

	/// true when the storage is open or exists under the storage root (never creates one)
	bool has_storage(protocol::storage_id const&) const;

	/// true while the replica of the storage is still catching up with its peers (plan 5.2)
	bool is_syncing(protocol::storage_id const&) const;

	/// the s2s listener endpoint when it is running (plan 4.1)
	std::optional<asio::ip::tcp::endpoint> s2s_local_endpoint() const;

	/// the last heads the given peer announced for the storage (plan 4.1/4.4)
	std::vector<origin_head> heads_of_peer(crypto::public_key_id const& peer, protocol::storage_id const&) const;

	/// ids of the peers with an authenticated live connection
	std::vector<crypto::public_key_id> connected_peers() const;
private:
	class impl;
	// encrypted_server requires this to be shared_ptr
	std::shared_ptr<impl> impl_;
};

}

