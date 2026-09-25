// SPDX-License-Identifier: MIT

#pragma once

#include "record_base.hpp"
#include "record_types.hpp"
#include "encrypted_record_header.hpp"
#include "segment_header.hpp"

#include <deque>

namespace securepath::sync {

/// The plain segment record data with non-encrypted data
class plain_segment_data {
public:
	plain_segment_data() = default;
	plain_segment_data(sequence_number start, sequence_number end, std::deque<record_tag> tags
		, record_tag previous_segment_tag = {})
	: segment_start_(start)
	, segment_end_(end)
	, tags_(std::move(tags))
	, previous_segment_tag_(std::move(previous_segment_tag))
	{}

	/// first sequence covered by this segment
	sequence_number segment_start() const { return segment_start_; }

	/// one past the last covered sequence; equals the segment record's own sequence
	sequence_number segment_end() const { return segment_end_; }

	/// tags of the covered records [segment_start, segment_end) in sequence order
	std::deque<record_tag> const& tags() const { return tags_; }

	/// tag of the previous segment record forming the segment backbone, empty for the first segment
	record_tag const& previous_segment_tag() const { return previous_segment_tag_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & segment_start_ & segment_end_ & tags_ & previous_segment_tag_ & trailing_data_;
	}

private:
	// Start and end of the segment in sequence numbers.
	// End sequence should be the same as the sequence of this record for now
	sequence_number segment_start_;
	sequence_number segment_end_;

	// Tags of the records in this segment in sequence number order starting from the smallest [segment_start, segment_end_)
	std::deque<record_tag> tags_;

	// tag of the previous segment record, empty for the first segment (the backbone, segments.txt S2)
	record_tag previous_segment_tag_;
	serialisation::trailing_data trailing_data_;
};

/// Segment record with encrypted header
class segment_record : public record_base {
public:
	static constexpr record_type_tag tag = segment_record_tag;

	segment_record() = default;
	segment_record(record_base base, plain_segment_data data, encrypted_record_header<segment_header> header)
	: record_base(std::move(base))
	, data_(std::move(data))
	, header_(std::move(header))
	{}

	/// Returns the plain segment data for this record
	plain_segment_data const& data() const { return data_; }

	/// Returns the encrypted header
	encrypted_record_header<segment_header> header() const { return header_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & static_cast<record_base&>(*this) & data_ & header_;
	}

private:
	plain_segment_data data_;
	encrypted_record_header<segment_header> header_;
};

}

