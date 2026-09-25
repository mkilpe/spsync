#pragma once

#include <spsync/core/records/equivocation_proof.hpp>

#include <securepath/database/connection.hpp>

#include <vector>

namespace securepath::sync {

/**
 * Per storage table of the equivocation proofs this replica found or was given (plan
 * 5.4). An origin with a proof against it is condemned: nothing it assigns is taken any
 * more. Kept in the storage database next to the record table.
 */
class evidence_store {
public:
	/// construct with the storage database connection; creates the table when missing
	explicit evidence_store(database::connection_ptr);

	/// keep the proof; false when one for its (origin, term, sequence) is held already
	bool record(equivocation_proof const&);

	/// a proof against the origin is held
	bool condemned(crypto::public_key_id const& origin) const;

	/// every proof held, in the order they were found
	std::vector<equivocation_proof> all() const;

private:
	database::connection_ptr db_;
};

}
