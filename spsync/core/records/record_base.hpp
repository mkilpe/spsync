#ifndef SPSYNC_CORE_RECORD_BASE_HEADER
#define SPSYNC_CORE_RECORD_BASE_HEADER

#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * The common parts in records.
 */
class record_base {
public:

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & structure_version_ & client_sequence_ & tag_ & iv_ & encryption_key_id_ & trailing_data_;
	}

private:
	// version of the current structure
	int structure_version_{1};

	// this is the last sequene the client has seen when pushing this record
	sequence_number client_sequence_;

	// tag of the previous record to form a chain
	octet_vector tag_;

	// initialisation vector for encrypting the record header
	octet_vector iv_;

	// the sequence number for the key used to encrypt this record
	sequence_number encryption_key_id_;

	serialisation::trailing_data trailing_data_;
};

}

#endif
