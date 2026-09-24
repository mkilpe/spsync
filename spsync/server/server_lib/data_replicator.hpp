#pragma once

#include "data_store.hpp"

#include <spsync/transfer/data_downloader.hpp>
#include <spsync/core/data/data_grant.hpp>
#include <spsync/protocol/protocol_base.hpp>

#include <securepath/network/encryption/context.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <vector>

namespace securepath::sync {

/// what a replicator needs of the data server it works for
struct data_replicator_hooks {
	/// the data store of a storage, created when the storage is new to this server
	std::function<std::shared_ptr<server_data_store>(protocol::storage_id const&)> store;

	/// the grant of a pull - a ticket with the right replicate and the holders to use it
	/// at - asked for when the pull starts; answered once, from any thread
	std::function<void(protocol::storage_id const&, data_descriptor const&
		, std::move_only_function<void(util::result<data_grant>)>)> ticket;

	/// a copy is complete here (RD13): the record servers are told
	std::function<void(protocol::storage_id const&, data_id const&)> complete;

	std::function<time_point()> now;
};

/**
 * The pulls of a data server (record_data.txt RD8/RD13, RDS 10): copies of data that
 * other data servers hold, fetched the way a member fetches them - the data protocol, a
 * record server's ticket, the manifest checked against the descriptor and every chunk
 * against the manifest (comm/net_data_channel and comm/data_downloader, one queue per
 * storage) - so a data server trusts another one no more than a member does. A pull that
 * ends early keeps its whole chunks and goes on when the record server asks again, which
 * it does with every replication sweep until the copy is announced.
 *
 * Thread safe; the hooks are called without the lock.
 */
class data_replicator {
public:
	data_replicator(network::context&, data_replicator_hooks, data_download_config = {}
		, std::chrono::seconds timeout = std::chrono::seconds{10});
	~data_replicator();

	/**
	 * Get copies of these data of the storage. A data that is complete here already is
	 * announced again (the asking record server did not know), one that cannot be held -
	 * quota, a descriptor out of bounds or contradicting what is known - is left out.
	 * Returns how many pulls were queued by this call.
	 */
	std::size_t replicate(protocol::storage_id const&, std::vector<data_descriptor> const&);

	/// pulls queued or on their way
	std::size_t pending() const;

	/// drop the queues and the connections; whole chunks are kept
	void close();

private:
	class impl;
	std::shared_ptr<impl> impl_;
};

}
