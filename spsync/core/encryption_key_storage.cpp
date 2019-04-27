#include "encryption_key_storage.hpp"
#include <spsync/core/error.hpp>

#include <securepath/serialisation/util.hpp>

namespace securepath::sync {

/*
	database table 'encryption_key_storage':
		seq: key sequence number as integer (primary key)
		key: encryption key as blob

*/

encryption_key_storage::encryption_key_storage(database::connection_ptr conn)
: db_(conn)
{
	if(!db_->prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='encryption_key_storage';").execute()) {
		db_->prepare("CREATE TABLE encryption_key_storage(seq INTEGER PRIMARY KEY, key BLOB);").execute();
	}
}

encryption_key encryption_key_storage::current_key() const {
	auto q = db_->prepare("SELECT * FROM encryption_key_storage WHERE seq = (SELECT max(seq) FROM encryption_key_storage);");
	auto res = q.execute();

	if(!res) {
		throw make_error(errc::no_encryption_key_set);
	}
	std::optional<octet_vector> data = res.value<octet_vector>(1);
	if(!data) {
		throw make_error(securepath::errc::invalid_data, "failed to get encryption key data column");
	}

	return serialisation::asn_der_deserialise<encryption_key>(*data);
}

std::optional<encryption_key> encryption_key_storage::find(util::sequence_number const& seq) const {
	auto q = db_->prepare("SELECT * FROM encryption_key_storage WHERE seq = :i LIMIT 1;");
	q.bind(":i", seq.value);
	auto res = q.execute();

	std::optional<encryption_key> result;
	if(res) {
		std::optional<octet_vector> data = res.value<octet_vector>(1);
		if(data) {
			result = serialisation::asn_der_deserialise<encryption_key>(*data);
		}
	}

	return result;
}

void encryption_key_storage::insert(encryption_key const& key) {
	octet_vector data = serialisation::asn_der_serialise(key);
	auto q = db_->prepare("INSERT OR REPLACE INTO encryption_key_storage VALUES(:a,:b);");
	q.bind(":a", key.key_seq.value);
	q.bind(":b", data);
	q.execute();
}

bool operator==(encryption_key const& left, encryption_key const& right) {
	return left.key_seq == right.key_seq && left.key == right.key;
}

bool operator!=(encryption_key const& left, encryption_key const& right) {
	return !(left == right);
}

}