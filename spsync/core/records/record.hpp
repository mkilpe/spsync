#ifndef SPSYNC_CORE_RECORD_HEADER
#define SPSYNC_CORE_RECORD_HEADER

#include "record_base.hpp"
#include <spsync/core/types.hpp>
#include <spsync/util/content_auth.hpp>

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

	record(record_type record, util::content_auth auth)
	: record_(std::move(record))
	, auth_(std::move(auth))
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
	util::content_auth auth_;

	// sequence from server, the only thing that is not protected by auth_ as the server sets it
	sequence_number server_sequence_;
};

class serialised_record {
public:
	template<typename RecordType>
	serialised_record(record<RecordType> const& record)
	: type_(RecordType::type)
	, record_(serialisation::asn_der_serialise(record))
	{
	}

	template<typename RecordType>
	serialised_record(RecordType rec, util::content_auth auth)
	: type_(RecordType::type)
	, record_(serialisation::asn_der_serialise(
		record<RecordType>(std::move(rec), std::move(auth))))
	{
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & type_ & record_;
	}

private:
	//type of the record as enum
	record_type_tag type_;
	//above record class as serialised
	octet_vector record_;
};

}

#endif
