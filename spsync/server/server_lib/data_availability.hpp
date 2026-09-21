#pragma once

#include <spsync/core/data/data_ticket.hpp>
#include <spsync/protocol/protocol_base.hpp>

#include <securepath/crypto/public_key_id.hpp>

#include <map>
#include <mutex>
#include <vector>

namespace securepath::sync {

/// what one data server holds of one data
struct data_holding {
	crypto::public_key_id holder;
	std::uint64_t have_chunks{};
	std::uint64_t total_chunks{};
	bool complete{};

	bool operator==(data_holding const&) const = default;
};

/// load signals of a data server (RD13)
struct holder_load {
	std::uint64_t stored_bytes{};
	std::uint32_t uploads_in_progress{};

	bool operator==(holder_load const&) const = default;
};

/**
 * The availability table of a record server (record_data.txt RD13): who holds what, as
 * the data servers announced it. Transient by design - a fresh announcement or ticket
 * gives the current view, nothing here is persisted and nothing depends on it being
 * complete: a data the table does not know is looked for in placement order.
 *
 * Thread safe.
 */
class data_availability {
public:
	/// what the holder has of the data now; replaces its earlier announcement. True when
	/// this is news of a complete copy: the holder was not known to hold all of it
	bool announce(protocol::storage_id const&, data_id const&, data_holding const&);

	/// no record names the data any more (RD9): nobody is asked for it again
	void forget(protocol::storage_id const&, data_id const&);

	void set_load(crypto::public_key_id const& holder, holder_load const&);

	/// the announced holdings of the data, in no particular order
	std::vector<data_holding> holdings(protocol::storage_id const&, data_id const&) const;

	/// the last load the holder announced; zero when it never did
	holder_load load(crypto::public_key_id const& holder) const;

private:
	using data_key = std::pair<protocol::storage_id, data_id>;

	mutable std::mutex mutex_;
	std::map<data_key, std::vector<data_holding>> holdings_;
	std::map<crypto::public_key_id, holder_load> loads_;
};

/**
 * Upload placement (RD13): the data servers in the order a data should go to them -
 * rendezvous hashing of (server key, data id), so the data spreads evenly over the set,
 * every record server names the same order without talking to the others, and a server
 * joining or leaving moves only the data that hashes to it. The first k entries are the
 * primary holders of a copy count k.
 */
std::vector<data_endpoint> upload_order(std::vector<data_endpoint> endpoints, data_id const&);

/**
 * Download holder ordering (RD13): complete holders first - the less loaded (uploads in
 * progress, then stored bytes) the earlier - then partial holders by how much they have,
 * then the servers nothing is known of in placement order, where an upload would have
 * gone. Holders that are not data servers of the storage are left out.
 */
std::vector<data_endpoint> download_order(std::vector<data_endpoint> const& endpoints, data_id const&
	, std::vector<data_holding> const& holdings, data_availability const& loads);

}
