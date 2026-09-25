// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/data/size_padding.hpp>
#include <spsync/core/types.hpp>

#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

/**
 * Header for a record, keeps the HeaderType as encrypted
 */
template<typename HeaderType>
class encrypted_record_header {
public:
	using header_type = HeaderType;

	encrypted_record_header() = default;

	explicit encrypted_record_header(octet_vector enc_header)
	: encrypted_header_(std::move(enc_header))
	{}

	/// Returns the raw encrypted data for the record header
	octet_vector const& data() const { return encrypted_header_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & encrypted_header_ & trailing_data_;
	}
private:
	octet_vector encrypted_header_;
	serialisation::trailing_data trailing_data_;
};

/**
 * The plaintext inside an encrypted record header (RD11, structure version 2): the
 * serialised header and zero padding up to its size class, so a message or an inline
 * payload leaks a size class and not its length. Readers never see the padding.
 */
struct padded_record_header {
	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & header & padding & trailing_data;
	}

public:
	octet_vector header;
	octet_vector padding;
	serialisation::trailing_data trailing_data;
};

/// the plaintext to encrypt for a header: its serialisation padded to the size class
inline octet_vector pad_record_header(octet_vector header) {
	std::uint64_t const padding = padded_size(header.size(), min_padded_header_size) - header.size();
	padded_record_header padded{std::move(header), octet_vector(padding)};
	return serialisation::asn_der_serialise(padded);
}

/// the serialised header out of a decrypted plaintext
inline octet_vector unpad_record_header(octet_vector const& plain) {
	return serialisation::asn_der_deserialise<padded_record_header>(plain).header;
}

}
