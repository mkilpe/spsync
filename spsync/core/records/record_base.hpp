#ifndef SPSYNC_CORE_RECORD_BASE_HEADER
#define SPSYNC_CORE_RECORD_BASE_HEADER

#include <spsync/core/types.hpp>
#include <securepath/serialisation/enum.hpp>

namespace securepath::sync {

/**
 * The common parts in records.
 */
class record_base {
public:

	record_base() = default;
	record_base(sequence_number last_seen_server_sequence, record_tag previous_tag, octet_vector iv, sequence_number enc_key_id)
	: last_seen_server_sequence_(std::move(last_seen_server_sequence))
	, previous_record_tag_(std::move(previous_tag))
	, iv_(std::move(iv))
	, encryption_key_id_(std::move(enc_key_id))
	{}

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & structure_version_ & last_seen_server_sequence_
			& previous_record_tag_ & iv_
			& encryption_key_id_ & trailing_data_;
	}

	octet_vector const& iv() const { return iv_; }
private:
	// version of the current structure
	int structure_version_{1};

	// this is the last sequence the client has seen when pushing this record
	sequence_number last_seen_server_sequence_;

	// tag of the previous record to form a chain
	record_tag previous_record_tag_;

	// initialisation vector for encrypting the record header
	octet_vector iv_;

	// the sequence number for the key used to encrypt this record
	sequence_number encryption_key_id_;

	serialisation::trailing_data trailing_data_;
};

/**
 * Types of the records for the serialised record
 */
enum class record_type_tag {
	unknown = 0,
	user_change_record,
	data_change_record,
	segment_record
};

serialisation::serialiser& serialise(serialisation::serialiser& s, record_type_tag const& v) {
	return securepath::serialisation::serialise(s, v);
}

serialisation::deserialiser& serialise(serialisation::deserialiser& s, record_type_tag& v) {
	return securepath::serialisation::serialise(s, v);
}


}

#endif
