#ifndef SPSYNC_SERVER_STORAGE_SERVER_CONTEXT_HEADER
#define SPSYNC_SERVER_STORAGE_SERVER_CONTEXT_HEADER

#include <spsync/core/sync_mode.hpp>
#include <spsync/protocol/protocol_base.hpp>

#include <memory>
#include <optional>

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

};

}

#endif
