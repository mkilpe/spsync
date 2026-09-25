#include "equivocation_proof.hpp"

#include <spsync/core/error.hpp>

namespace securepath::sync {

error equivocation_proof::verify(octet_vector const& storage_id, crypto::public_key_access const& keys) const {
	if(auto err = first_.verify(storage_id, keys)) {
		return err;
	}
	if(auto err = second_.verify(storage_id, keys)) {
		return err;
	}
	bool const same_assignment = first_.origin() == second_.origin() && first_.term() == second_.term()
		&& first_.block().sequence() == second_.block().sequence();
	if(!same_assignment) {
		return make_error(sync::errc::not_authentic, "the envelopes assign different sequences");
	}
	if(first_.block().hash() == second_.block().hash()) {
		return make_error(sync::errc::not_authentic, "the envelopes assign the sequence to the same record");
	}
	return {};
}

}
