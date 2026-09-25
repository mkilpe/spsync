// SPDX-License-Identifier: MIT

#include "data_state_table.hpp"

#include <securepath/crypto/hash.hpp>

#include <spsync/core/database_util.hpp>

#include <securepath/database/util.hpp>
#include <securepath/serialisation/util.hpp>

#include <utility>

namespace securepath::sync {
namespace {

char const* const row_columns = "key, data_id, enc_size, chunk_size, state, have";

// construct a row from a query selecting row_columns
std::optional<data_state_row> extract_row(database::query const& q) {
	std::optional<data_state_row> ret;
	if(q) {
		auto key = q.value<std::int64_t>(0);
		auto id = q.value<octet_vector>(1);
		auto state = q.value<std::int64_t>(4);
		if(!key || !id || !state) {
			throw make_error(securepath::errc::invalid_data, "failed to interpret record data columns");
		}
		data_state_row row;
		row.local_id = static_cast<std::uint64_t>(*key);
		row.descriptor.manifest_digest = std::move(*id);
		row.descriptor.enc_size = static_cast<std::uint64_t>(q.value<std::int64_t>(2).value_or(0));
		row.descriptor.chunk_size = static_cast<std::uint32_t>(q.value<std::int64_t>(3).value_or(0));
		row.state = static_cast<record_data_state>(*state);
		row.have = have_bitmap{row.descriptor.chunk_count(), q.value<octet_vector>(5).value_or(octet_vector{})};
		ret = std::move(row);
	}
	return ret;
}

}

/*
	database table 'record_data':
		key: row id as integer (primary key), the data_ref of record_objects
		data_id: manifest digest as blob
		enc_size: total size of the encrypted chunks
		chunk_size: plaintext octets per chunk
		state: record_data_state as integer
		have: bitmap of the held chunks as blob (have_bitmap)
		digests: the manifest's chunk digests as one blob, null until known (a table from
			before this column carries them in `manifest`, moved over on open)
		header: serialised data_header as blob, null until a record carrying it was read
		content_digest: the header's content digest as blob (indexed), null like the header
*/

data_state_table::data_state_table(database::connection_ptr db)
: db_(std::move(db))
{
	if(!db_->has_table("record_data")) {
		db_->prepare("CREATE TABLE record_data("
			// autoincrement: the key of a removed row is never given to another data - a
			// handle or a record_objects.data_ref that outlived its row must not find a stranger
			"key INTEGER PRIMARY KEY AUTOINCREMENT,"
			"data_id BLOB UNIQUE,"
			"enc_size INTEGER,"
			"chunk_size INTEGER,"
			"state INTEGER,"
			"have BLOB,"
			"digests BLOB,"
			"header BLOB,"
			"content_digest BLOB);").execute();
	} else {
		if(!has_column(*db_, "record_data", "header")) {
			// a database from before RDS 6
			db_->prepare("ALTER TABLE record_data ADD COLUMN header BLOB;").execute();
			db_->prepare("ALTER TABLE record_data ADD COLUMN content_digest BLOB;").execute();
		}
		if(!has_column(*db_, "record_data", "digests")) {
			// a database from before the digests were kept as one blob: the serialised
			// manifests move over, one digest is readable on its own from then on
			db_->prepare("ALTER TABLE record_data ADD COLUMN digests BLOB;").execute();
			migrate_manifests();
		}
	}
	db_->prepare("CREATE INDEX IF NOT EXISTS record_data_content ON record_data(content_digest);").execute();
}

void data_state_table::migrate_manifests() {
	auto q = db_->prepare("SELECT key, manifest FROM record_data WHERE manifest IS NOT NULL;");
	std::vector<std::pair<std::int64_t, data_manifest>> manifests;
	for(auto res = q.execute(); res; res.next()) {
		manifests.emplace_back(res.value<std::int64_t>(0).value_or(0), database::extract_column_type<data_manifest>(res, 1));
	}
	database::transaction tact(*db_);
	for(auto const& [key, manifest] : manifests) {
		auto u = db_->prepare("UPDATE record_data SET digests = :d, manifest = NULL WHERE key = :k;");
		u.bind(":d", manifest.octets());
		u.bind(":k", key);
		u.execute();
	}
}

data_state_table::data_state_table(database::connection_ptr db, existing_schema)
: db_(std::move(db))
{
}

std::uint64_t data_state_table::ensure(data_descriptor const& d) {
	// the row sizes a bitmap from the descriptor: not from one that names no or countless chunks
	if(!usable_data_descriptor(d)) {
		throw make_error(securepath::errc::invalid_data, "record data descriptor out of bounds");
	}
	// two threads may meet here for the same data: the insert of the second is a no-op
	auto insert = db_->prepare(
		"INSERT INTO record_data(data_id, enc_size, chunk_size, state, have)"
		" VALUES(:id, :enc, :chunk, :state, :have) ON CONFLICT(data_id) DO NOTHING;");
	insert.bind(":id", d.manifest_digest);
	insert.bind(":enc", static_cast<std::int64_t>(d.enc_size));
	insert.bind(":chunk", static_cast<std::int64_t>(d.chunk_size));
	insert.bind(":state", static_cast<std::int64_t>(std::to_underlying(record_data_state::deferred)));
	insert.bind(":have", have_bitmap{d.chunk_count()}.octets());
	insert.execute();

	auto row = find(d.manifest_digest);
	if(!row) {
		throw make_error(securepath::errc::invalid_state, "failed to create record data row");
	}
	return row->local_id;
}

std::optional<data_state_row> data_state_table::find(data_id const& id) const {
	auto q = db_->prepare(std::string("SELECT ") + row_columns + " FROM record_data WHERE data_id = :id;");
	q.bind(":id", id);
	return extract_row(q.execute());
}

std::optional<data_state_row> data_state_table::find(std::uint64_t local_id) const {
	auto q = db_->prepare(std::string("SELECT ") + row_columns + " FROM record_data WHERE key = :k;");
	q.bind(":k", static_cast<std::int64_t>(local_id));
	return extract_row(q.execute());
}

std::vector<std::uint64_t> data_state_table::all_ids() const {
	auto q = db_->prepare("SELECT key FROM record_data ORDER BY key ASC;");
	std::vector<std::uint64_t> ret;
	for(auto res = q.execute(); res; res.next()) {
		ret.push_back(static_cast<std::uint64_t>(res.value<std::int64_t>(0).value_or(0)));
	}
	return ret;
}

std::uint64_t data_state_table::total_enc_size() const {
	auto q = db_->prepare("SELECT sum(enc_size) FROM record_data;");
	// a sum is a plain integer
	return static_cast<std::uint64_t>(q.execute().value<std::int64_t>(0).value_or(0));
}

void data_state_table::set_state(std::uint64_t local_id, record_data_state state) {
	auto q = db_->prepare("UPDATE record_data SET state = :state WHERE key = :k;");
	q.bind(":state", static_cast<std::int64_t>(std::to_underlying(state)));
	q.bind(":k", static_cast<std::int64_t>(local_id));
	q.execute();
}

void data_state_table::set_have(std::uint64_t local_id, have_bitmap const& have) {
	auto q = db_->prepare("UPDATE record_data SET have = :have WHERE key = :k;");
	q.bind(":have", have.octets());
	q.bind(":k", static_cast<std::int64_t>(local_id));
	q.execute();
}

void data_state_table::set_manifest(std::uint64_t local_id, data_manifest const& manifest) {
	auto q = db_->prepare("UPDATE record_data SET digests = :m WHERE key = :k;");
	q.bind(":m", manifest.octets());
	q.bind(":k", static_cast<std::int64_t>(local_id));
	q.execute();
}

std::optional<data_manifest> data_state_table::manifest(std::uint64_t local_id) const {
	auto q = db_->prepare("SELECT digests FROM record_data WHERE key = :k;");
	q.bind(":k", static_cast<std::int64_t>(local_id));
	std::optional<data_manifest> ret;
	auto res = q.execute();
	auto const octets = res ? res.value<octet_vector>(0) : std::nullopt;
	if(octets) {
		ret = data_manifest::from_octets(*octets);
	}
	return ret;
}

bool data_state_table::has_manifest(std::uint64_t local_id) const {
	auto q = db_->prepare("SELECT digests IS NOT NULL FROM record_data WHERE key = :k;");
	q.bind(":k", static_cast<std::int64_t>(local_id));
	auto res = q.execute();
	return res && res.value<std::int64_t>(0).value_or(0) != 0;
}

std::optional<octet_vector> data_state_table::chunk_digest(std::uint64_t local_id, std::uint64_t chunk_no) const {
	// substr counts from one; a digest past the end comes back short and is none
	auto const size = static_cast<std::int64_t>(crypto::hash_digest_size());
	auto q = db_->prepare("SELECT substr(digests, :from, :size) FROM record_data WHERE key = :k AND digests IS NOT NULL;");
	q.bind(":from", static_cast<std::int64_t>(chunk_no) * size + 1);
	q.bind(":size", size);
	q.bind(":k", static_cast<std::int64_t>(local_id));
	auto res = q.execute();
	auto digest = res ? res.value<octet_vector>(0) : std::nullopt;
	if(digest && digest->size() != static_cast<std::size_t>(size)) {
		digest.reset();
	}
	return digest;
}

void data_state_table::set_header(std::uint64_t local_id, data_header const& header) {
	auto q = db_->prepare("UPDATE record_data SET header = :h, content_digest = :c WHERE key = :k;");
	q.bind(":h", serialisation::asn_der_serialise(header));
	q.bind(":c", header.content_digest);
	q.bind(":k", static_cast<std::int64_t>(local_id));
	q.execute();
}

std::optional<data_header> data_state_table::header(std::uint64_t local_id) const {
	auto q = db_->prepare("SELECT header FROM record_data WHERE key = :k;");
	q.bind(":k", static_cast<std::int64_t>(local_id));
	std::optional<data_header> ret;
	auto res = q.execute();
	if(res && res.value<octet_vector>(0)) {
		ret = database::extract_column_type<data_header>(res, 0);
	}
	return ret;
}

std::vector<data_state_row> data_state_table::find_by_content(octet_vector const& content_digest) const {
	auto q = db_->prepare(std::string("SELECT ") + row_columns + " FROM record_data WHERE content_digest = :c ORDER BY key ASC;");
	q.bind(":c", content_digest);
	std::vector<data_state_row> ret;
	for(auto res = q.execute(); res; res.next()) {
		if(auto row = extract_row(res)) {
			ret.push_back(std::move(*row));
		}
	}
	return ret;
}

database::transaction data_state_table::transaction() {
	return database::transaction{*db_};
}

void data_state_table::remove(std::uint64_t local_id) {
	auto q = db_->prepare("DELETE FROM record_data WHERE key = :k;");
	q.bind(":k", static_cast<std::int64_t>(local_id));
	q.execute();
}

}
