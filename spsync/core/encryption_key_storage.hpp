// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/util/sequence_number.hpp>
#include <securepath/database/connection.hpp>
#include <securepath/serialisation/sequence.hpp>

#include <memory>

namespace securepath::sync {

/*
 * Key and sequence number pair
 */
struct encryption_key {
	util::sequence_number key_seq;
	octet_vector key;
	serialisation::trailing_data trailing_data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & key_seq & key & trailing_data;
	}
};


//t: add some kind of pending key concept, for example, the key sequence might change there is conflicting change while synchronising the user change record

/**
 * Storage to keep encryption keys and query those by the key id
 *
 */
class encryption_key_storage {
public:
	/// construct with database connection
	encryption_key_storage(database::connection_ptr);

	encryption_key_storage(encryption_key_storage const&) = delete;
	encryption_key_storage operator=(encryption_key_storage const&) = delete;

	/// returns the current encryption key to use (key with highest sequence number;
	/// colliding keys of that sequence are ordered by carrier tag, plan 4.6/D9)
	encryption_key current_key() const;

	/// returns encryption key with given sequence number if it exists; when concurrent
	/// key rotations collided on the sequence, the carrier tag order decides (D9)
	std::optional<encryption_key> find(util::sequence_number const&) const;

	/**
	 * All keys stored for the sequence, in the deterministic order. Concurrent key
	 * rotations can produce different keys under one sequence (D9: both are kept);
	 * decryption tries each candidate.
	 */
	std::vector<encryption_key> find_all(util::sequence_number const&) const;

	/**
	 * Insert an encryption key. A key already known for its sequence is kept as well
	 * (union, D9); carrier_tag is the tag of the user change record that delivered the
	 * key and makes the collision order deterministic across replicas.
	 */
	void insert(encryption_key const& key, octet_vector const& carrier_tag = {});

	/// get the sequence number of the latest key
	util::sequence_number last_seq() const;

	/// create new key with next sequence number
	encryption_key create_key();

	/// get all encryption keys
	std::vector<encryption_key> export_keys() const;
private:
	database::connection_ptr db_;
};

bool operator==(encryption_key const& left, encryption_key const& right);

}

