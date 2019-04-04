#ifndef SPSYNC_CORE_RECORD_BASE_HEADER
#define SPSYNC_CORE_RECORD_BASE_HEADER

#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * The common parts in records.
 */
class record_base {
public:

	/// sets the server sequence number
	void set_server_sequence(sequence_number const&);


	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & structure_version_ & iv_ & encryption_key_id_ & client_sequence_ & auth_ & server_sequence_ & trailing_data_;
	}

private:
	//version of the current structure
	int structure_version_{1};

	//initialisation vector for encryption
	octet_vector iv_;

	//the sequence number for the key used to encrypt this record
	sequence_number encryption_key_id_;

	//this is the last sequene the client has seen when pushing this record
	sequence_number client_sequence_;

	//signature/tag that protects the data in the record
	content_auth auth_;

	//sequence from server, the only thing that is not protected as the server sets it
	sequence_number server_sequence_;

	serialisation::trailing_data trailing_data_;
};

}

#endif
