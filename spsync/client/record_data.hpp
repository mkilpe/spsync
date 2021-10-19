#pragma once

#include <spsync/core/users.hpp>
#include <spsync/core/records/data_change_record.hpp>
#include <spsync/core/record_interface.hpp>

namespace securepath::sync {

struct single_data_change {
	plain_single_change_data data;
	data_change_header header;

	//notice that this is the record data, so it is not continuous when looking only into data changes (and not set if the record is still pending)
	sequence_number seq;

	//unique id to look up the record from record storage
	record_internal_id internal_id;

	//if the record is signed, this contains the public key id that was used to sign it
	std::optional<crypto::public_key_id> signer;
};

struct user_change {
	users members;
	util::metadata metadata;

	//if the record is signed, this contains the public key id that was used to sign it
	std::optional<crypto::public_key_id> signer;
};

}
