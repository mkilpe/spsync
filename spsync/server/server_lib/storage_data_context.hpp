#pragma once

#include "ticket_issuer.hpp"

#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/protocol/protocol_base.hpp>
#include <spsync/protocol/s2s_protocol.hpp>

#include <securepath/crypto/public_key_id.hpp>

#include <cstdint>
#include <vector>

namespace securepath::sync {

class storage;

/**
 * The record data side of what a connection to the record role uses (record_data.txt
 * RD12/RD13): tickets, the data servers of the storages and what they announce. The
 * record side proper is storage_server_context; a connection takes both, the data
 * coordinator implements this one.
 */
class storage_data_context {
protected:
	~storage_data_context() = default;

public:
	/// the ticket for a data of the storage, issued to the member, with the data servers to use it at
	virtual util::result<issued_ticket> issue_data_ticket(storage const&, data_id const&,
		crypto::public_key_id const& member, std::uint32_t right) = 0;

	/// the data-role servers of the storages of this server: the endpoint list of the storage info
	virtual std::vector<data_endpoint> data_endpoints() const = 0;

	/// a peer announced what its data role holds
	virtual void data_announced(protocol::announce_data const&) = 0;

	/**
	 * True for the key of a configured data-role server that is no replication peer (the
	 * separate data server of RD12): it may connect to the s2s listener to announce what
	 * it holds, and nothing else.
	 */
	virtual bool is_data_server(crypto::public_key_id const&) const = 0;

	/// the ticket of a replication pull (RD13 copy count) for a data server of this server:
	/// right replicate, with the complete holders to pull from
	virtual util::result<issued_ticket> issue_replica_ticket(protocol::storage_id const&, data_id const&,
		crypto::public_key_id const& data_server) = 0;

	/// what this server's own data role holds, as announcements for a peer whose link
	/// just came up; empty without a data role
	virtual std::vector<protocol::announce_data> own_data_announcements() = 0;
};

}
