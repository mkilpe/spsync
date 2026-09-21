#pragma once

#include "data_descriptor.hpp"

#include <securepath/crypto/private_key.hpp>
#include <securepath/crypto/public_key_access.hpp>
#include <securepath/crypto/public_key_id.hpp>
#include <securepath/crypto/signature.hpp>

#include <string>

namespace securepath::sync {

/// what a data ticket allows; the values are part of the signed ticket, never renumber
enum class data_right : std::uint32_t {
	upload = 1,
	download = 2,
	/// a download by a data server that is to hold a copy (RD8/RD13 replication): issued
	/// to data servers only, served like a download but outside the storage's transfer
	/// quota - that one is about what members move
	replicate = 3
};

/// a data-role server of a storage (RD12): where it listens and the key that authenticates it
struct data_endpoint {
	bool operator==(data_endpoint const&) const = default;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & host & port & key & region & trailing_data;
	}

public:
	std::string host;
	std::uint16_t port{};
	/// public key id of the data server's key
	crypto::public_key_id key;
	/// optional locality label for the holder ordering (RD13)
	std::string region;
	serialisation::trailing_data trailing_data;
};

/**
 * The permission to move one data to or from a data server (RD12). A data server has no
 * chain: it can check neither membership nor a manifest against a committed record, so
 * the record server that can states both - this member may upload/download the data with
 * this descriptor in this storage until the expiry - and signs it. The ticket names the
 * data, not the server: it is valid at any holder that trusts the issuer.
 */
class data_ticket {
public:
	data_ticket() = default;
	data_ticket(octet_vector storage_id, data_descriptor descriptor, crypto::public_key_id member
		, data_right right, time_point expiry);

	octet_vector const& storage_id() const { return storage_id_; }
	data_descriptor const& descriptor() const { return descriptor_; }
	/// the data the ticket is for: the descriptor's manifest digest
	data_id const& data() const { return descriptor_.manifest_digest; }
	crypto::public_key_id const& member() const { return member_; }
	data_right right() const { return static_cast<data_right>(right_); }
	time_point expiry() const { return expiry_; }
	/// the record server that signed the ticket; invalid while unsigned
	crypto::public_key_id issuer() const { return signature_.issuer(); }
	bool is_signed() const { return signature_.is_valid(); }

	void sign(crypto::private_key const& record_server_key);

	/**
	 * The signature is the issuer's and the ticket has not expired. Whether the issuer
	 * is a record server this holder accepts tickets from is the caller's to check.
	 */
	[[nodiscard]] error verify(crypto::public_key_access const& keys, time_point now) const;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & storage_id_ & descriptor_ & member_ & right_ & expiry_ & signature_ & trailing_data_;
	}

private:
	octet_vector digest() const;

private:
	octet_vector storage_id_;
	data_descriptor descriptor_;
	crypto::public_key_id member_;
	std::uint32_t right_{};
	time_point expiry_;
	crypto::signature signature_;
	serialisation::trailing_data trailing_data_;
};

}
