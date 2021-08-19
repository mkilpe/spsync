#ifndef SPSYNC_CORE_CHAIN_BLOCK_HEADER
#define SPSYNC_CORE_CHAIN_BLOCK_HEADER

#include "record_base.hpp"
#include "record_types.hpp"
#include <spsync/core/types.hpp>
#include <spsync/util/content_auth.hpp>

#include <securepath/crypto/hash.hpp>
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
 * Contains the serialised record<RecordType> class, authentication information and the server set block information
 */
class chain_block {
public:
	chain_block() = default;

	template<typename RecordType>
	chain_block(auth_record<RecordType> record, sequence_number s)
	: record_(serialisation::asn_der_serialise_choice<record_types>(record.record))
	, auth_(std::move(record.auth))
	, sequence_(s)
	{
	}

	template<typename RecordType>
	chain_block(auth_record<RecordType> record)
	: chain_block(record, record.record.last_seen_block().sequence + 1)
	{
	}

	template<typename RecordType>
	chain_block(RecordType const& rec, util::content_auth auth)
	: record_(serialisation::asn_der_serialise_choice<record_types>(rec))
	, auth_(std::move(auth))
	{
	}

	/// Returns the sequence number, this is either set by server (final) or prediction by client
	sequence_number sequence() const {
		return sequence_;
	}

	/// Returns the hash of the previous chain block
	octet_vector const& parent_hash() const {
		return parent_hash_;
	}

	/// sets the sequence number and the parent hash
	void set_sequence_and_parent_hash(sequence_number s, octet_vector hash) {
		sequence_ = s;
		parent_hash_ = std::move(hash);
	}

	/// Returns the tag of this record
	octet_vector tag() const {
		return auth_.tag();
	}

	/// check if records are identical without considering the server assigned data
	bool check_matches_without_server_data(chain_block const& rec) const {
		return record_ == rec.record_ &&
				auth_ == rec.auth_;
	}

	/// get the authentication part for the record
	util::content_auth auth() const { return auth_; }

	/// the block hash that is used for the parent hash
	octet_vector hash() const {
		return crypto::hash(serialisation::asn_der_serialise(*this), crypto::hash_algorithm::sha3_512);
	}

	chain_block_id id() const {
		return chain_block_id{sequence_, hash()};
	}

	/// check if there is any data in the block chain
	bool is_valid() const {
		return !record_.empty();
	}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & record_ & auth_ & sequence_ & parent_hash_;
	}

	/**
	 * Helper function to deserialise the contained record type for handling
	 *
	 * The visitor type needs to have call-operator for the RecordType types.
	 * Example:
	 *  struct visitor { void operator()(user_change_record record); ... };
	 */
	template<typename Visitor>
	void deserialise_record(Visitor&& v) const {
		deserialise_record<void>(std::forward<Visitor>(v));
	}

	template<typename ReturnType, typename Visitor>
	ReturnType deserialise_record(Visitor&& v) const {
		return serialisation::asn_der_deserialise_choice<record_types, ReturnType>(record_, std::forward<Visitor>(v));
	}

	template<typename Record>
	Record deserialise_to() const {
		return deserialise_record<Record>([](auto const& rec){ return rec; });
	}

	template<typename Record>
	auth_record<Record> to_auth_record() const {
		return auth_record<Record>(deserialise_to<Record>(), auth());
	}

private:
	//the specific record class as serialised
	octet_vector record_;

	// signature/tag that protects the data in the record
	util::content_auth auth_;

	// sequence from server (final) or prediction by client, not protected by auth_ as the server sets it
	sequence_number sequence_;

	// hash of the previous chain block, not protected by auth_ as the server sets it
	octet_vector parent_hash_;
};

}

#endif
