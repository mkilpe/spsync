// SPDX-License-Identifier: MIT

#include "evidence_store.hpp"

#include <securepath/log/log.hpp>
#include <securepath/serialisation/util.hpp>

#include <ctime>
#include <utility>

namespace securepath::sync {

/*
	database table 'equivocation_evidence':
		origin: public key id of the origin server as blob
		term: consensus term of the assignments as integer (0 until phase 6)
		seq: the sequence assigned twice as integer
		proof: the DER encoded equivocation_proof as blob
		found: when it was recorded, seconds since the epoch
*/

evidence_store::evidence_store(database::connection_ptr db)
: db_(std::move(db))
{
	if(!db_->has_table("equivocation_evidence")) {
		db_->prepare("CREATE TABLE equivocation_evidence("
			"origin BLOB,"
			"term INTEGER,"
			"seq INTEGER,"
			"proof BLOB,"
			"found INTEGER,"
			"PRIMARY KEY(origin, term, seq));").execute();
	}
}

bool evidence_store::record(equivocation_proof const& proof) {
	database::transaction tact(*db_);
	auto held = db_->prepare("SELECT count(*) FROM equivocation_evidence WHERE origin = :o AND term = :t AND seq = :s;");
	held.bind(":o", proof.origin().data());
	held.bind(":t", proof.term());
	held.bind(":s", proof.sequence().value);
	if(held.execute().value<std::int64_t>(0).value_or(0) != 0) {
		return false;
	}
	auto q = db_->prepare(
		"INSERT INTO equivocation_evidence(origin, term, seq, proof, found) VALUES(:o, :t, :s, :p, :f);");
	q.bind(":o", proof.origin().data());
	q.bind(":t", proof.term());
	q.bind(":s", proof.sequence().value);
	q.bind(":p", serialisation::asn_der_serialise(proof));
	q.bind(":f", static_cast<std::int64_t>(std::time(nullptr)));
	q.execute();
	return true;
}

bool evidence_store::condemned(crypto::public_key_id const& origin) const {
	auto q = db_->prepare("SELECT count(*) FROM equivocation_evidence WHERE origin = :o;");
	q.bind(":o", origin.data());
	auto res = q.execute();
	return res.value<std::int64_t>(0).value_or(0) != 0;
}

std::vector<equivocation_proof> evidence_store::all() const {
	std::vector<equivocation_proof> ret;
	auto q = db_->prepare("SELECT proof FROM equivocation_evidence ORDER BY found, rowid;");
	auto res = q.execute();
	for(; res; res.next()) {
		if(auto proof = res.value<octet_vector>(0)) {
			ret.push_back(serialisation::asn_der_deserialise<equivocation_proof>(*proof));
		}
	}
	return ret;
}

}
