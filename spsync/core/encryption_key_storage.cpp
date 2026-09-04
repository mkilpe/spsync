#include "encryption_key_storage.hpp"
#include <spsync/core/error.hpp>

#include <securepath/crypto/random.hpp>
#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

/*
	database table 'encryption_key_storage':
		seq: key sequence number as integer
		key: encryption key as blob
		carrier_tag: tag of the user change record that delivered the key (empty for own
		             created keys); orders colliding keys of one sequence (plan 4.6/D9)

	Concurrent key rotations on different replicas can produce different keys under the
	same sequence; all of them are kept (D9). The pick for a sequence is ordered by the
	key bytes: carrier tags are not replica stable (a key can be re-delivered by a later
	invite), the key bytes are - every replica picks the same one.
*/

encryption_key_storage::encryption_key_storage(database::connection_ptr conn)
: db_(conn)
{
	auto q = db_->prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='encryption_key_storage';");
	if(!q.execute()) {
		db_->prepare("CREATE TABLE encryption_key_storage(seq INTEGER, key BLOB, carrier_tag BLOB,"
			" UNIQUE(seq, key));").execute();
	}
}

encryption_key encryption_key_storage::current_key() const {
	auto q = db_->prepare("SELECT key FROM encryption_key_storage"
		" WHERE seq = (SELECT max(seq) FROM encryption_key_storage)"
		" ORDER BY key ASC LIMIT 1;");
	auto res = q.execute();

	if(!res) {
		throw make_error(errc::no_encryption_key_set);
	}
	std::optional<octet_vector> data = res.value<octet_vector>(0);
	if(!data) {
		throw make_error(securepath::errc::invalid_data, "failed to get encryption key data column");
	}

	return serialisation::asn_der_deserialise<encryption_key>(*data);
}

std::optional<encryption_key> encryption_key_storage::find(util::sequence_number const& seq) const {
	auto q = db_->prepare("SELECT key FROM encryption_key_storage WHERE seq = :i"
		" ORDER BY key ASC LIMIT 1;");
	q.bind(":i", seq.value);
	auto res = q.execute();

	std::optional<encryption_key> result;
	if(res) {
		std::optional<octet_vector> data = res.value<octet_vector>(0);
		if(data) {
			result = serialisation::asn_der_deserialise<encryption_key>(*data);
		}
	}

	return result;
}

std::vector<encryption_key> encryption_key_storage::find_all(util::sequence_number const& seq) const {
	auto q = db_->prepare("SELECT key FROM encryption_key_storage WHERE seq = :i"
		" ORDER BY key ASC;");
	q.bind(":i", seq.value);

	std::vector<encryption_key> ret;
	auto res = q.execute();
	for(; res; res.next()) {
		std::optional<octet_vector> data = res.value<octet_vector>(0);
		if(data) {
			ret.push_back(serialisation::asn_der_deserialise<encryption_key>(*data));
		}
	}
	return ret;
}

void encryption_key_storage::insert(encryption_key const& key, octet_vector const& carrier_tag) {
	LOG_TRACE("encryption_key_storage::insert (seq={}) {}", key.key_seq, static_cast<void const*>(this));

	octet_vector data = serialisation::asn_der_serialise(key);
	auto q = db_->prepare("INSERT OR IGNORE INTO encryption_key_storage(seq, key, carrier_tag)"
		" VALUES(:a, :b, :c);");
	q.bind(":a", key.key_seq.value);
	q.bind(":b", data);
	q.bind(":c", carrier_tag);
	q.execute();
}

util::sequence_number encryption_key_storage::last_seq() const {
	auto q = db_->prepare("SELECT max(seq) FROM encryption_key_storage;");
	auto res = q.execute();

	return util::sequence_number{res ? res.value<std::uint64_t>(0).value_or(0ULL): 0ULL};
}

encryption_key encryption_key_storage::create_key() {
	encryption_key res;

	res.key_seq = last_seq()+1;
	res.key = crypto::random_octet_vector(32);
	insert(res);

	return res;
}

std::vector<encryption_key> encryption_key_storage::export_keys() const {
	auto q = db_->prepare("SELECT * FROM encryption_key_storage;");
	auto res = q.execute();

	std::vector<encryption_key> result;
	for(; res; res.next()) {
		std::optional<octet_vector> data = res.value<octet_vector>(1);
		if(data) {
			result.push_back(serialisation::asn_der_deserialise<encryption_key>(*data));
		}
	}

	return result;
}

bool operator==(encryption_key const& left, encryption_key const& right) {
	return left.key_seq == right.key_seq && left.key == right.key;
}

}