#pragma once

#include "data_replicator.hpp"
#include "data_store.hpp"
#include "peer_config.hpp"

#include <spsync/protocol/ports.hpp>
#include <spsync/protocol/protocol_base.hpp>
#include <spsync/protocol/s2s_protocol.hpp>

#include <securepath/network/encryption/context.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace securepath::sync {

using namespace std::chrono_literals;

struct data_server_params {
	/// the data role is optional (record_data.txt RD12): same binary, own listener and port
	bool enabled{};

	std::uint16_t data_port{default_data_server_port};

	/// this will override the above port if set
	std::optional<asio::ip::tcp::endpoint> data_endpoint;

	asio::ip::tcp::endpoint create_endpoint() const;

	/// connecting/handshake timeout
	std::chrono::seconds timeout{10s};

	/// root path of the storages: the data of a storage lives in <root>/<sid hex>/data.db
	/// and <root>/<sid hex>/data/, next to the record role's storage.db when there is one
	std::string storage_root{"record-storages"};

	/// resource quota of every storage on this server (RD10), 0 = no limit
	data_quota quota;

	/// transfer quota of every storage on this server: served octets per window (RD10)
	transfer_quota transfer;

	/**
	 * The record servers of this data server (RD12) as host:port/keyid-hex of their s2s
	 * listener: their tickets are accepted, and a link is kept to each to announce what
	 * is held here (RD13) - the link is also how their keys are learned. The server's
	 * own key is always accepted: an all-in-one server issues tickets to itself and
	 * hears of completions directly (storage_server::attach_data_role), its own entry
	 * in a shared cluster configuration is dropped. An entry without a host is trusted
	 * for tickets only, no link is kept to it.
	 */
	std::vector<peer_config> record_servers;

	/// the pulls of copies this server is to hold (RD13 replication): queue sizes as for a client
	data_download_config replication;

	/// an upload nothing touched for this long is dropped and its reservation freed
	std::chrono::seconds incomplete_upload_expiry{24h};

	/// how often the expiry runs
	std::chrono::seconds expiry_check_interval{600s};
};

/**
 * The data role of a server (record_data.txt RD12, RDS 4): a listener of its own where
 * clients with a certified key upload record data with a ticket a record server signed.
 * Content-blind and chain-blind: tickets say what belongs here, manifests what it must
 * look like.
 */
class data_server {
public:
	/// a data became complete on this server
	using complete_handler = std::function<void(protocol::storage_id const&, data_id const&)>;

	data_server(network::context&, data_server_params = {});
	~data_server();

	void start();
	void close();

	/// the listener endpoint when it is running (the real port when started with port 0)
	std::optional<asio::ip::tcp::endpoint> local_endpoint() const;

	/// where completions are announced (RD13); the record server link sets this (RDS 5)
	void set_complete_handler(complete_handler);

	/// the data store of a storage, e.g. for tooling and tests
	std::shared_ptr<server_data_store> open_store(protocol::storage_id const&);

	/// run the expiry of incomplete uploads now over the open stores; returns how many went
	std::size_t expire_incomplete();

	/**
	 * Drop data of a storage no record names any more (RD9): called by the record role
	 * of an all-in-one server, and for a release_data a configured record server sent
	 * over its link. Returns how many were held here.
	 */
	std::size_t release(protocol::storage_id const&, std::vector<data_id> const&);

	/// how the pulls this server's own record role asked for get their tickets (an
	/// all-in-one server, storage_server::attach_data_role); answered once, from any thread
	using replica_ticket_source = std::function<void(protocol::storage_id const&, data_descriptor const&
		, std::move_only_function<void(util::result<data_grant>)>)>;
	void set_replica_ticket_source(replica_ticket_source);

	/**
	 * Hold copies of these data of a storage (RD8/RD13 replication, RDS 10): called by
	 * the record role of an all-in-one server, and for a replicate_data a configured
	 * record server sent over its link. The copies are pulled from the data servers that
	 * hold them, with a ticket of the record server that asked, and announced when
	 * complete. Returns how many pulls were queued by this call.
	 */
	std::size_t replicate(protocol::storage_id const&, std::vector<data_descriptor> const&);

	/// pulls queued or on their way
	std::size_t pending_replications() const;

	/// what one data of a storage looks like here; nullopt when it is not known
	std::optional<data_state_row> find(protocol::storage_id const&, data_id const&);

	/// every complete data of the open stores with its storage (RD13 announcements)
	std::vector<std::pair<protocol::storage_id, data_state_row>> complete_holdings();

	/// load signals (RD13): octets reserved by the known data, uploads in progress
	std::uint64_t stored_bytes();
	std::uint64_t uploads_in_progress();

	/**
	 * Everything held completely as availability announcements of the given holder, in
	 * batches that stay well under a transport frame; an empty one still carries the
	 * load. For a link that just came up (RD13).
	 */
	std::vector<protocol::announce_data> announcements(crypto::public_key_id const& holder);

	/// one data as an announcement with the current load; nullopt when it is not known here
	std::optional<protocol::announce_data> announcement(crypto::public_key_id const& holder, protocol::storage_id const&, data_id const&);

	/// the record servers a link is up to (tests and tooling)
	std::vector<crypto::public_key_id> connected_record_servers() const;

private:
	class impl;
	// encrypted_server requires this to be shared_ptr
	std::shared_ptr<impl> impl_;
};

}
