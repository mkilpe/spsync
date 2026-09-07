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

	/// An already open storage, or null; never creates one
	virtual std::shared_ptr<storage> find_open_sync(protocol::storage_id const&) = 0;

	/**
	 * The replicated storage a peer refers to (plan 4.2/4.4): an open one, else one found
	 * on disk (opened now, e.g. after a restart), else - when the peer states replicated
	 * modes - a new one created with exactly those modes, so a storage created on one
	 * replica appears on the others. Null when nothing applies (the answer is
	 * not_replicating): peers never create unreplicated storages and never change modes.
	 */
	virtual std::shared_ptr<storage> acquire_replica(protocol::storage_id const&, std::optional<storage_modes> peer_modes) = 0;

	/// The resolved server identity (plan 3.3); empty when the server has no signing key
	virtual server_identity const& identity() const = 0;

	/**
	 * Remember an authenticated peer's public key (its certificate chain was verified in the
	 * handshake and its id matched the peer configuration) so the assignments it signs
	 * verify here (plan 4.2)
	 */
	virtual void trust_peer_key(crypto::public_key const&) = 0;

	/// a public key of a record signer learned from a peer (plan 5.2); it is checked to be
	/// self authentic and to match the id that was asked for before it is stored
	virtual void learn_signer_key(crypto::public_key const&) = 0;

	/// a public key this server holds, for a peer's request_key
	virtual std::optional<crypto::public_key> find_key(crypto::public_key_id const&) const = 0;

	/**
	 * The storage is still catching up (plan 5.2): it is bootstrapping, or a connected
	 * peer announced a head we have not reached. Clients are answered storage_syncing so
	 * they try another replica.
	 */
	virtual bool is_syncing(protocol::storage_id const&) = 0;

	/// a heads exchange or a pull chain for the storage found nothing more to fetch from
	/// a peer: when no connected peer is ahead any more, the bootstrap is over
	virtual void note_caught_up(protocol::storage_id const&) = 0;

	/// Ids of the open storages that replicate to peers (replication mode != none)
	virtual std::vector<protocol::storage_id> replicated_storages() const = 0;
};

}

