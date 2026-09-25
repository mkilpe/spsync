#pragma once

#include "chain_sync.hpp"
#include "storage_heads.hpp"

#include <spsync/core/divergence.hpp>
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
	 * storage has different modes, construction throws storage_mode_mismatch. Without
	 * create_modes only an existing storage opens: an unknown id throws no_such_storage
	 * (a plain load never leaves a default mode storage behind).
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

	/// forwarded to chain_sync: one origin's envelopes by origin sequence (plan 4.4)
	std::deque<block_envelope> get_envelopes_by_origin(crypto::public_key_id const& origin,
		sequence_number from, sequence_number to) const;

	/**
	 * The highest sequence we hold of the given origin (plan 4.4): the last record we
	 * assigned ourselves for our own origin (plan 5.2), the origin head table entry
	 * otherwise (invalid when unknown).
	 */
	sequence_number known_origin_seq(crypto::public_key_id const& origin) const;

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

	/**
	 * History cut at a committed segment (segments.txt SEG 5) and the rollback of plan
	 * 3.1, with what follows for record data (record_data.txt RD9/RDS 9): the rows of
	 * the record data index that no record references any more go, and the data release
	 * hook is told, so the data servers drop the chunks. The data of retained records
	 * stays - record data follows its records. A cut also applies the retention policy
	 * of the storage (storage_limits::kept_data_versions): the data of the versions of an
	 * object beyond the newest kept ones below the segment is pruned - the records stay,
	 * tickets for the data are refused with data_pruned and the data servers release it
	 * like the data of removed records. Both return the removed blocks. These are
	 * the entry points for whatever triggers a cut or a rollback: going to the chain log
	 * directly leaves the data behind.
	 */
	std::vector<chain_block> cut_history(record_tag const& segment_tag);
	std::vector<chain_block> truncate_from(sequence_number first_removed);

	using data_release_hook = std::function<void(protocol::storage_id const&, std::vector<data_id> const&)>;

	/// set by the storage server: tells the data servers of data no record names any more
	void set_data_release(data_release_hook);

	using peer_push_hook = std::function<void(protocol::storage_id const&, storage_modes const&, block_envelope const&)>;

	/// set by the storage server: fans a committed envelope out to the connected peers
	void set_peer_push(peer_push_hook);

	void add_listener(std::shared_ptr<connection> const&);

	/// tell the listeners that a data server holds a data of this storage (RD4 notify_data)
	void notify_data(data_id const&, bool complete);

	/**
	 * The descriptor of a data a record of this storage names, from the record data index
	 * the record storage keeps (record_data.txt RDS 2). What a data ticket is issued
	 * from (RD12). Errors (protocol errc): unknown_data for a data no stored record
	 * references, data_pruned for one the retention policy let go at a history cut.
	 */
	util::result<data_descriptor> committed_data(data_id const&) const;

	/**
	 * The heads anti-entropy exchanges for this storage (plan 3.4): the own live head
	 * from the log (when the server has a signing key, term 0 until phase 6) followed by
	 * the stored heads of the other origins.
	 */
	std::vector<origin_head> heads() const;

	/// the history samples behind the heads (plan 5.3): one entry per announced origin
	std::vector<origin_samples> history_samples() const;

	/// where this replica's view of an origin parts from a peer's samples of it (plan 5.3)
	divergence find_divergence(origin_samples const&) const;

	/// the stored per-origin heads; phase 4 records foreign heads here when applying
	storage_heads& origin_heads() { return *heads_; }

	/**
	 * A replica created from a peer's announcement is bootstrapping until the heads of
	 * every connected peer are covered (plan 5.2); persisted so a restart in the middle
	 * keeps answering clients with storage_syncing. Never set for a locally created
	 * storage.
	 */
	bool bootstrapping() const;
	void set_bootstrapping(bool);

private:
	std::optional<block_envelope> make_envelope(chain_block const&) const;
	/// requires the mutex released: drop the dead index rows and tell the release hook
	void release_dead_data(std::vector<data_id> pruned = {});
	void notify_listeners(chain_block const& c, std::optional<block_envelope> const&);
	/// requires the mutex; listeners that went away are dropped on the way
	void for_each_listener(std::function<void(connection&)> const&);

private:
	mutable std::mutex mutex_;
	storage_config config_;
	protocol::storage_id id_;
	storage_modes modes_;
	crypto::public_key_access* keys_{};
	crypto::private_data_access* private_data_{};
	peer_push_hook peer_push_;
	data_release_hook data_release_;

	std::unique_ptr<chain_sync> sync_;
	std::unique_ptr<storage_heads> heads_;
	database::connection_ptr db_;
	/// id of the server signing key; invalid when the server has no key
	crypto::public_key_id own_id_;
	bool bootstrapping_{};
	std::unordered_map<void const*, std::weak_ptr<connection>> listeners_;
};

}

