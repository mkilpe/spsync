#pragma once

#include <spsync/core/error.hpp>
#include <spsync/core/origin_head.hpp>

#include <securepath/database/connection.hpp>

#include <optional>
#include <vector>

namespace securepath::sync {

/**
 * Per storage table of the highest (term, seq, hash) seen from each origin server
 * (plan 3.4). Kept in the storage database next to the record table; the own live head
 * comes from chain_log and is composed in by storage::heads().
 */
class storage_heads {
public:
	/// construct with the storage database connection; creates the table when missing
	explicit storage_heads(database::connection_ptr);

	/**
	 * Store the head when it is newer than the stored one for that origin, ordered by
	 * (term, sequence); returns true when stored. An equal (term, sequence) under a
	 * different hash is not newer (that is equivocation evidence, handled by the caller).
	 * The origin and the block id must be valid.
	 */
	bool advance(origin_head const&);

	/// the stored head of the origin
	std::optional<origin_head> find(crypto::public_key_id const&) const;

	/// all stored heads
	std::vector<origin_head> all() const;

	/// remove the stored head of the origin
	void remove(crypto::public_key_id const&);

private:
	database::connection_ptr db_;
};

}
