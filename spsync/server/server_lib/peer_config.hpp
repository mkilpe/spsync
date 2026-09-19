#pragma once

#include <spsync/core/data/data_ticket.hpp>
#include <spsync/core/error.hpp>
#include <spsync/util/format.hpp>

#include <securepath/crypto/public_key_id.hpp>

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

namespace securepath::sync {

/**
 * A replication peer of this server (plan 3.3): the storage server endpoint and the public
 * key id of the peer's server signing key (ML-DSA), which authenticates the peer in the
 * server-to-server handshake (plan 4.1).
 */
struct peer_config {
	/// host name or address; IPv6 addresses without the brackets
	std::string host;
	std::uint16_t port{};
	/// public key id of the peer's server signing key
	crypto::public_key_id key;

	bool operator==(peer_config const&) const = default;
};

/// parsed from "host:port/keyid-hex"; IPv6 hosts in brackets ("[::1]:4711/ab01...")
std::istream& operator>>(std::istream&, peer_config&);
std::ostream& operator<<(std::ostream&, peer_config const&);
std::string to_string(peer_config const&);

/**
 * A data-role server in the cluster configuration of a record server (record_data.txt
 * RD12), parsed from "host:port/keyid-hex" with an optional "/region" label at the end
 */
std::istream& operator>>(std::istream&, data_endpoint&);
std::ostream& operator<<(std::ostream&, data_endpoint const&);

/// The resolved identity of this server: its signing key id and its replication peers.
struct server_identity {
	crypto::public_key_id server_id;
	std::vector<peer_config> peers;
};

/**
 * Resolve the server identity from configuration against the actual server key (plan 3.3).
 * A non-empty configured id must match the actual key id and any peer configuration
 * requires a server key, otherwise invalid_configuration is thrown; so a server cannot
 * come up signing with a different identity than it was configured for. The own entry is
 * dropped from the peer list so one shared cluster configuration can be used; duplicate
 * peer key ids are refused.
 */
server_identity resolve_server_identity(std::string const& configured_id, std::vector<peer_config> peers,
	crypto::public_key_id const& actual);

/**
 * The peers that replicate a storage: the given subset of known peer key ids resolved
 * against the known peers (plan 3.3). An empty subset means every known peer; a subset id
 * that is not a known peer throws invalid_configuration.
 */
std::vector<peer_config> replicating_peers(std::vector<crypto::public_key_id> const& subset,
	std::vector<peer_config> const& known);

}


SPSYNC_FORMAT_VIA_TO_STRING(securepath::sync::peer_config)
