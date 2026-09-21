#pragma once

#include "data_availability.hpp"

#include <spsync/util/result.hpp>

#include <securepath/crypto/private_key.hpp>

#include <chrono>
#include <optional>
#include <vector>

namespace securepath::sync {

/// what a ticket request is answered with (RD12/RD13)
struct issued_ticket {
	data_ticket ticket;
	std::vector<data_endpoint> holders;
};

/**
 * The record role's ticket issuing (record_data.txt RD12/RD13): a ticket is the record
 * server's statement that a committed record of the storage names the data - the caller
 * looked the descriptor up in the chain - issued to the asking member for a short while,
 * together with the data servers to use it at: placement order for an upload, the
 * availability table's view for a download. Every ticket is issued here, so the order
 * of that list is the load balancing.
 */
class ticket_issuer {
public:
	ticket_issuer(std::vector<data_endpoint> data_servers, data_availability const&, std::chrono::seconds validity);

	/// the data servers of the storages of this server (the endpoint list of the storage info)
	std::vector<data_endpoint> const& data_servers() const { return data_servers_; }

	/**
	 * committed is the descriptor of the data when a record of the storage names it, else
	 * the reason no ticket is to be had for it (storage::committed_data: unknown_data,
	 * data_pruned), which is what comes back. Other errors (protocol errc):
	 * no_data_servers, invalid_state (not a right, no server key to sign with).
	 */
	util::result<issued_ticket> issue(protocol::storage_id const&, util::result<data_descriptor> const& committed
		, crypto::public_key_id const& member, std::uint32_t right
		, std::optional<crypto::private_key> const& server_key, time_point now) const;

	/**
	 * The ticket of a replication pull (RD8/RD13): right replicate - which no member gets
	 * through issue() - for a data server of the storages of this server, with the
	 * complete holders to pull from in download order. Errors as issue(), and invalid_state
	 * for a key that is no data server here, data_not_held when no other server is known
	 * to hold the data completely.
	 */
	util::result<issued_ticket> issue_replica(protocol::storage_id const&, util::result<data_descriptor> const& committed
		, crypto::public_key_id const& data_server
		, std::optional<crypto::private_key> const& server_key, time_point now) const;

private:
	/// what stands in the way of any ticket, no error when nothing does
	error refusal(util::result<data_descriptor> const& committed, std::optional<crypto::private_key> const& server_key) const;

private:
	std::vector<data_endpoint> const data_servers_;
	data_availability const& availability_;
	std::chrono::seconds const validity_;
};

}
