#pragma once

#include "chain_sync.hpp"
#include <spsync/core/records/block_envelope.hpp>
#include "storage_config.hpp"

#include <spsync/protocol/protocol_base.hpp>

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

	struct commit_outcome {
		util::result<chain_block> block;
		/// the signed sequence assignment; set when the server has a signing key
		std::optional<block_envelope> envelope;
	};

	/// forwarded to chain_sync; on success the envelope is signed once and shared by the
	/// commit response and the listener notifications
	commit_outcome commit_block(chain_block const&);

	void add_listener(std::shared_ptr<connection> const&);

private:
	std::optional<block_envelope> make_envelope(chain_block const&) const;
	void notify_listeners(chain_block const& c, std::optional<block_envelope> const&);

private:
	mutable std::mutex mutex_;
	storage_config config_;
	protocol::storage_id id_;
	storage_modes modes_;
	crypto::private_data_access* private_data_{};

	std::unique_ptr<chain_sync> sync_;
	std::unordered_map<void const*, std::weak_ptr<connection>> listeners_;
};

}

