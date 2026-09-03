#pragma once

#include "chain_sync.hpp"
#include "storage_heads.hpp"
#include <spsync/core/records/block_envelope.hpp>
#include "storage_config.hpp"

#include <spsync/protocol/protocol_base.hpp>

#include <functional>
#include <mutex>
#include <unordered_map>

namespace securepath::crypto {
	class private_data_access;
}

namespace securepath::sync {

class connection;

/// Contains what is needed to manipulate a single record storage
class storage {
public:
	/**
	 * Open (or create) the record storage. The modes are persisted in the storage database on
	 * first creation and are immutable afterwards; when create_modes is given and an existing
	 * storage has different modes, construction throws storage_mode_mismatch.
	 */
	storage(protocol::storage_id id, storage_config config, std::optional<storage_modes> create_modes = {},
		crypto::public_key_access* keys = nullptr, crypto::private_data_access* private_data = nullptr);
	virtual ~storage() = default;

	/// Id of this record storage
	protocol::storage_id id() const { return id_; }

	/// The persisted modes of this storage
	storage_modes modes() const { return modes_; }

	/// forwarded to chain_sync
	sequence_number current_sequence_number() const;

	/// forwarded to chain_sync
	std::deque<chain_block> get_records(sequence_number start, sequence_number end) const;

	/// forwarded to chain_sync: envelopes for the s2s pull (plan 4.1)
	std::deque<block_envelope> get_envelopes(sequence_number start, sequence_number end) const;

	struct commit_outcome {
		util::result<chain_block> block;
		/// the signed sequence assignment; set when the server has a signing key
		std::optional<block_envelope> envelope;
	};

	/// forwarded to chain_sync; on success the envelope is signed once and shared by the
	/// commit response and the listener notifications; weak replication pushes the
	/// envelope to the peers through the peer push hook (plan 4.2)
	commit_outcome commit_block(chain_block const&);

	/**
	 * Apply a record another server committed (plan 4.2, weak mode): the origin's
	 * envelope signature and the client signature are verified, known tags/op ids are
	 * ignored, otherwise the block is validated with the weak rules and applied under
	 * our own sequence. The origin's signed assignment is what the log keeps (it carries
	 * origin id + origin sequence for anti-entropy) and the origin head is advanced.
	 * Foreign records are never pushed onward (peers pull the rest, plan 4.4).
	 */
	error apply_foreign(block_envelope const&);

	using peer_push_hook = std::function<void(protocol::storage_id const&, block_envelope const&)>;

	/// set by the storage server: fans a committed envelope out to the connected peers
	void set_peer_push(peer_push_hook);

	void add_listener(std::shared_ptr<connection> const&);

	/**
	 * The heads anti-entropy exchanges for this storage (plan 3.4): the own live head
	 * from the log (when the server has a signing key, term 0 until phase 6) followed by
	 * the stored heads of the other origins.
	 */
	std::vector<origin_head> heads() const;

	/// the stored per-origin heads; phase 4 records foreign heads here when applying
	storage_heads& origin_heads() { return *heads_; }

private:
	std::optional<block_envelope> make_envelope(chain_block const&) const;
	void notify_listeners(chain_block const& c, std::optional<block_envelope> const&);

private:
	mutable std::mutex mutex_;
	storage_config config_;
	protocol::storage_id id_;
	storage_modes modes_;
	crypto::public_key_access* keys_{};
	crypto::private_data_access* private_data_{};
	peer_push_hook peer_push_;

	std::unique_ptr<chain_sync> sync_;
	std::unique_ptr<storage_heads> heads_;
	/// id of the server signing key; invalid when the server has no key
	crypto::public_key_id own_id_;
	std::unordered_map<void const*, std::weak_ptr<connection>> listeners_;
};

}

