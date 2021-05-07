#ifndef SPSYNC_SERVER_STORAGE_SERVER_CONTEXT_HEADER
#define SPSYNC_SERVER_STORAGE_SERVER_CONTEXT_HEADER

#include <spsync/protocol/protocol_base.hpp>

#include <memory>

namespace securepath::sync {

class storage;

/// Context interface individual connections will use to operate
class storage_server_context {
protected:
	~storage_server_context() = default;

public:

	/// Acquire storage object to manipulate the given record storage
	virtual std::shared_ptr<storage> acquire_sync(protocol::storage_id const& id) = 0;

	/// Release the storage object
	virtual void release_sync(std::shared_ptr<storage> storage) = 0;

};

}

#endif
