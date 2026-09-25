// SPDX-License-Identifier: MIT

#include "storage_heads.hpp"

#include <securepath/log/log.hpp>

#include <utility>

namespace securepath::sync {

/*
	database table 'storage_heads':
		origin: public key id of the origin server as blob (primary key)
		term: consensus term of the head block as integer (0 until phase 6)
		seq: sequence of the head block as integer
		hash: hash of the head block as blob
*/

storage_heads::storage_heads(database::connection_ptr db)
: db_(std::move(db))
{
	if(!db_->has_table("storage_heads")) {
		db_->prepare("CREATE TABLE storage_heads("
			"origin BLOB PRIMARY KEY,"
			"term INTEGER,"
			"seq INTEGER,"
			"hash BLOB);").execute();
	}
}

bool storage_heads::advance(origin_head const& head) {
	if(!head.origin.is_valid() || !head.block.is_valid()) {
		throw make_error(sync::errc::constraint_violation, "advancing an invalid origin head");
	}

	database::transaction tact(*db_);

	auto const existing = find(head.origin);
	bool const newer = !existing || std::pair{existing->term, existing->block.sequence}
		< std::pair{head.term, head.block.sequence};
	if(newer) {
		auto q = db_->prepare(
			"INSERT INTO storage_heads(origin, term, seq, hash) VALUES(:o, :t, :s, :h)"
			" ON CONFLICT(origin) DO UPDATE SET term = excluded.term, seq = excluded.seq, hash = excluded.hash;");
		q.bind(":o", head.origin.data());
		q.bind(":t", head.term);
		q.bind(":s", head.block.sequence.value);
		q.bind(":h", head.block.hash);
		q.execute();
	}
	return newer;
}

std::optional<origin_head> storage_heads::find(crypto::public_key_id const& origin) const {
	auto q = db_->prepare("SELECT term, seq, hash FROM storage_heads WHERE origin = :o;");
	q.bind(":o", origin.data());

	std::optional<origin_head> ret;
	auto res = q.execute();
	if(res) {
		ret = origin_head{origin
			, res.value<std::uint64_t>(0).value_or(0)
			, chain_block_id{res.value<std::uint64_t>(1).value_or(0), res.value<octet_vector>(2).value_or(octet_vector{})}};
	}
	return ret;
}

std::vector<origin_head> storage_heads::all() const {
	auto q = db_->prepare("SELECT origin, term, seq, hash FROM storage_heads ORDER BY origin;");

	std::vector<origin_head> ret;
	auto res = q.execute();
	for(; res; res.next()) {
		auto origin = res.value<octet_vector>(0);
		if(!origin) {
			LOG_WARN("invalid storage heads entry, no origin set");
			throw make_error(securepath::errc::invalid_data, "failed to interpret storage heads columns");
		}
		ret.push_back(origin_head{crypto::public_key_id{std::move(*origin)}
			, res.value<std::uint64_t>(1).value_or(0)
			, chain_block_id{res.value<std::uint64_t>(2).value_or(0), res.value<octet_vector>(3).value_or(octet_vector{})}});
	}
	return ret;
}

void storage_heads::remove(crypto::public_key_id const& origin) {
	auto q = db_->prepare("DELETE FROM storage_heads WHERE origin = :o;");
	q.bind(":o", origin.data());
	q.execute();
}

}
