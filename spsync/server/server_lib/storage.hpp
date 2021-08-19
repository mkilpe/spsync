#ifndef SPSYNC_SERVER_STORAGE_HEADER
#define SPSYNC_SERVER_STORAGE_HEADER

#include "chain_sync.hpp"
#include "storage_config.hpp"

#include <spsync/protocol/protocol_base.hpp>

#include <mutex>
#include <unordered_set>

namespace securepath::sync {

class connection;

/// Contains what is needed to manipulate a single record storage
class storage {
public:
	storage(protocol::storage_id id, storage_config config);
	virtual ~storage() = default;

	/// Id of this record storage
	protocol::storage_id id() const { return id_; }

	/// forwarded to chain_sync
	sequence_number current_sequence_number() const;

	/// forwarded to chain_sync
	std::deque<chain_block> get_records(sequence_number start, sequence_number end) const;

	/// forwarded to chain_sync
	util::result<chain_block> commit_block(chain_block const&);

	void add_listener(std::shared_ptr<connection> const&);

private:
	void notify_listeners(chain_block const& c);

private:
	mutable std::mutex mutex_;
	storage_config config_;
	protocol::storage_id id_;

	std::unique_ptr<chain_sync> sync_;
	std::unordered_map<void const*, std::weak_ptr<connection>> listeners_;
};

}

#endif
