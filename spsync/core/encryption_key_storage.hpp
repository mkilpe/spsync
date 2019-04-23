#ifndef SPSYNC_CORE_ENCRYPTION_KEY_STORAGE_HEADER
#define SPSYNC_CORE_ENCRYPTION_KEY_STORAGE_HEADER

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

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & key_seq & key;
	}
};


/**
 * Storage to keep encryption keys and query those by the key id
 *
 */
class encryption_key_storage {
public:
	/// construct with database connection
	encryption_key_storage(database::connection_ptr);

	/// returns the current encryption key to use (key with highest sequence number)
	encryption_key current_key() const;

	/// returns encryption key with given sequence number is exists
	std::optional<encryption_key> find(util::sequence_number const&) const;

	/// insert encryption key to the storage
	void insert(encryption_key const& key);
private:
	database::connection_ptr db_;
};

bool operator==(encryption_key const& left, encryption_key const& right);
bool operator!=(encryption_key const& left, encryption_key const& right);

}

#endif