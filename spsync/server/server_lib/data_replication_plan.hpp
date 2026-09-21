#pragma once

#include "data_availability.hpp"

#include <functional>
#include <map>
#include <optional>
#include <vector>

namespace securepath::sync {

/// what the record storage says of a data that data servers hold
struct data_standing {
	/// set when a record names the data and the retention policy has not let it go
	std::optional<data_descriptor> descriptor;
	/// certainly not wanted any more: pruned, or unknown to a storage no other record
	/// server could know better (one that does not replicate)
	bool dead{};
};

/// what a record server sees when it looks after the copies (RD13 copy count)
struct replication_view {
	std::vector<data_endpoint> const& data_servers;
	data_availability const& availability;
	std::size_t copies{};
	/// a data server this record server can tell now: its own data role, a connected link
	std::function<bool(crypto::public_key_id const&)> reachable;
	std::function<data_standing(protocol::storage_id const&, data_id const&)> standing;
};

struct replication_plan {
	/// data server -> storage -> the data it is to get a copy of
	std::map<crypto::public_key_id, std::map<protocol::storage_id, std::vector<data_descriptor>>> copies;
	/// storage -> data that are held though no record wants them (a release that was missed)
	std::map<protocol::storage_id, std::vector<data_id>> stale;

	bool empty() const { return copies.empty() && stale.empty(); }
};

/**
 * Look after the copies of the given data (record_data.txt RD13, RDS 10): a primary
 * holder - the first `copies` servers of the placement order - without a complete copy
 * is to get one as soon as some data server holds the data completely, if it can be told
 * now and the record storage vouches for the data (tickets for the pull are issued from
 * the same statement). A data the storage has certainly let go is stale where it is held:
 * that is how a release_data a data server missed is made up for. The standing is asked
 * only for data somebody holds completely.
 */
replication_plan plan_replication(replication_view const&, std::vector<std::pair<protocol::storage_id, data_id>> const& data);

}
