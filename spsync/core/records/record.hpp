#ifndef SPSYNC_CORE_RECORD_HEADER
#define SPSYNC_CORE_RECORD_HEADER

#include "record_base.hpp"
#include <spsync/core/types.hpp>
#include <spsync/util/content_auth.hpp>

#include <securepath/serialisation/sequence.hpp>
#include <securepath/serialisation/util.hpp>
#include <securepath/util/typelist.hpp>

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


/**
 * Types of the records for the serialised record
 */
enum record_type_tag {
	user_change_record_tag = 1,
	data_change_record_tag,
	segment_record_tag
};

class user_change_record;
class data_change_record;
class segment_record;

using serialisation::type_tag;

/// typelist for serialising choice
using record_types = typelist<
			type_tag<record<user_change_record>, user_change_record_tag>,
			type_tag<record<data_change_record>, data_change_record_tag>,
			type_tag<record<segment_record>, segment_record_tag> >;


/**
 * Contains the serialised record<RecordType> class for easy use in network protocol
 */
class serialised_record {
public:
	serialised_record() = default;

	template<typename RecordType>
	serialised_record(record<RecordType> const& record)
	: record_(serialisation::asn_der_serialise_choice<record_types>(record))
	{
	}

	/// As above but construct the record<RecordType> on the fly
	template<typename RecordType>
	serialised_record(RecordType rec, util::content_auth auth)
	: record_(serialisation::asn_der_serialise_choice<record_types>(
		record<RecordType>(std::move(rec), std::move(auth))))
	{
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & record_;
	}

	/**
	 * Helper function to deserialise the contained record type for handling
	 *
	 * The visitor type needs to have call-operator for the record<RecordType> types.
	 * Example:
	 *  struct visitor { void operator()(record<user_change_record> rec); ... };
	 */
	template<typename Visitor>
	void deserialise_record(octet_span data, Visitor& v) {
		serialisation::asn_der_deserialise_choice<record_types>(data, v);
	}

private:
	//above record class as serialised
	octet_vector record_;
};

}

#endif
