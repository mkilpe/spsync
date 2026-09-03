#pragma once

#include "peer_config.hpp"

#include <spsync/core/sync_mode.hpp>
#include <spsync/protocol/protocol_base.hpp>

#include <memory>
#include <optional>
#include <vector>

namespace securepath::sync {

class storage;

/// Context interface individual connections will use to operate
class storage_server_context {
protected:
	~storage_server_context() = default;

public:

	/**
	 * Acquire storage object to manipulate the given record storage. create_modes is set when
	 * the client requests specific modes (create_storage); an existing storage with different
	 * modes causes storage_mode_mismatch to be thrown.
	 */
	virtual std::shared_ptr<storage> acquire_sync(protocol::storage_id const& id, std::optional<storage_modes> create_modes = {}) = 0;

	/// Release the storage object
	virtual void release_sync(std::shared_ptr<storage> storage) = 0;

	/// An already open storage, or null; never creates one (the s2s handlers use this,
	/// a peer must not create storages on this server, plan 4.2)
	virtual std::shared_ptr<storage> find_open_sync(protocol::storage_id const&) = 0;

	/// The resolved server identity (plan 3.3); empty when the server has no signing key
	virtual server_identity const& identity() const = 0;

	/// Ids of the open storages that replicate to peers (replication mode != none)
	virtual std::vector<protocol::storage_id> replicated_storages() const = 0;
};

}

