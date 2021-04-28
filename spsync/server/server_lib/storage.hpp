#ifndef SPSYNC_SERVER_STORAGE_HEADER
#define SPSYNC_SERVER_STORAGE_HEADER

#include "chain_sync.hpp"
#include <spsync/protocol/protocol_base.hpp>

namespace securepath::sync {

class storage {
public:
	storage(protocol::storage_id const& id);
	virtual ~storage() = default;

private:
	std::unique_ptr<chain_sync> sync_;
};

}

#endif
