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
 * Holds record and the authentication data
 */
template<typename RecordType>
class auth_record {
public:
	using record_type = RecordType;

	auth_record(record_type record, util::content_auth auth)
	: record(std::move(record))
	, auth(std::move(auth))
	{}

	// the actual record data that is authenticated by the auth_
	record_type record;

	// signature/tag that protects the data in the record
	util::content_auth auth;
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
			type_tag<user_change_record, user_change_record_tag>,
			type_tag<data_change_record, data_change_record_tag>,
			type_tag<segment_record, segment_record_tag> >;


/**
 * Contains the serialised record<RecordType> class for easy use in network protocol
 */
class serialised_record {
public:
	serialised_record() = default;

	template<typename RecordType>
	serialised_record(auth_record<RecordType> record, sequence_number const& s = {})
	: record_(serialisation::asn_der_serialise_choice<record_types>(record.record))
	, auth_(std::move(record.auth))
	, server_sequence_(s)
	{
	}

	template<typename RecordType>
	serialised_record(RecordType const& rec, util::content_auth auth)
	: record_(serialisation::asn_der_serialise_choice<record_types>(rec))
	, auth_(std::move(auth))
	{
	}

	/// Returns the sequence number set by the server
	sequence_number server_sequence() const {
		return server_sequence_;
	}

	/// sets the server sequence number
	void set_server_sequence(sequence_number const& s) {
		server_sequence_ = s;
	}

	/// Returns the tag of this record (the tag is used to chain the records)
	octet_vector tag() const {
		return auth_.tag();
	}

	bool check_matches_without_seq(serialised_record const& rec) const {
		return record_ == rec.record_ &&
				auth_ == rec.auth_;
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & record_ & auth_ & server_sequence_;
	}

	/**
	 * Helper function to deserialise the contained record type for handling
	 *
	 * The visitor type needs to have call-operator for the RecordType types.
	 * Example:
	 *  struct visitor { void operator()(user_change_record'rec); ... };
	 */
	template<typename Visitor>
	void deserialise_record(octet_span data, Visitor& v) {
		serialisation::asn_der_deserialise_choice<record_types>(data, v);
	}

private:
	//the specific record class as serialised
	octet_vector record_;

	// signature/tag that protects the data in the record
	util::content_auth auth_;

	// sequence from server, the only thing that is not protected by auth_ as the server sets it
	sequence_number server_sequence_;
};

}

#endif
