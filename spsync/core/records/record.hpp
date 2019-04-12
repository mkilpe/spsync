#ifndef SPSYNC_CORE_RECORD_HEADER
#define SPSYNC_CORE_RECORD_HEADER

#include <spsync/core/types.hpp>

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

/**
 * Holds record and the authentication data for it along side with the server sequence number
 */
template<typename RecordType>
class record {
public:
	using record_type = RecordType;

	record(record_type record)
	: record_(std::move(record))
	{}

	/// sets the server sequence number
	void set_server_sequence(sequence_number const& s) {
		server_sequence_ = s;
	}

	/// Returns the tag of this record (the tag is used to chain the records)
	octet_vector tag() const {
		return auth_.tag();
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & record_ & auth_ & server_sequence_;
	}

private:
	// the actual record data that is authenticated by the auth_
	record_type record_;

	// signature/tag that protects the data in the record
	content_auth auth_;

	// sequence from server, the only thing that is not protected by auth_ as the server sets it
	sequence_number server_sequence_;
};

class serialised_record {
public:
	template<typename RecordType>
	serialised_record(record<RecordType> const& record)
	: record_(serialisation::asn_der_serialise(record));
	{
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & record_;
	}

private:
	//above record class as serialised
	octet_vector record_;
};

}

#endif
