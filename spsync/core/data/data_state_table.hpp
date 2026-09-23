#pragma once

#include "data_descriptor.hpp"
#include "data_manifest.hpp"
#include "have_bitmap.hpp"

#include <spsync/core/record_data.hpp>
#include <securepath/database/connection.hpp>

#include <optional>
#include <vector>

namespace securepath::sync {

/// one row of the data table
struct data_state_row {
	/// the row id: record_data::local_id and record_objects.data_ref
	std::uint64_t local_id{};
	data_descriptor descriptor;
	record_data_state state{record_data_state::unknown};
	have_bitmap have;
};

/**
 * The bookkeeping of record data (RD6): one row per data_id with the descriptor's
 * server-visible half, the local state, the have-bitmap and the manifest once it is
 * known. The chunks themselves are files (chunk_files). The record storage points its
 * object rows here (record_objects.data_ref), so a row exists for every data a stored
 * record names, held or not; on a server the rows are the index of the data the chain
 * refers to.
 *
 * Individual calls are thread safe the way the record storage is; a read-modify-write
 * of the bitmap is the caller's to serialise (record_data_store does).
 */
class data_state_table {
public:
	/// for a database whose owner made the table when it was opened: nothing is checked
	struct existing_schema {};
	explicit data_state_table(database::connection_ptr);
	data_state_table(database::connection_ptr, existing_schema);

	/// the row of the descriptor's data, created as deferred with nothing held when unknown
	std::uint64_t ensure(data_descriptor const&);

	std::optional<data_state_row> find(data_id const&) const;
	std::optional<data_state_row> find(std::uint64_t local_id) const;

	/// every row id, ascending
	std::vector<std::uint64_t> all_ids() const;

	/// the enc_size of every row added up: what the known data takes when all of it is held
	std::uint64_t total_enc_size() const;

	void set_state(std::uint64_t local_id, record_data_state);
	void set_have(std::uint64_t local_id, have_bitmap const&);

	void set_manifest(std::uint64_t local_id, data_manifest const&);
	std::optional<data_manifest> manifest(std::uint64_t local_id) const;

	/**
	 * The members-only half of the descriptor, once a record was read that carries it
	 * (clients only; it lives in the local database like the group keys do). Its content
	 * digest is indexed: the same content under another data id need not be downloaded.
	 */
	void set_header(std::uint64_t local_id, data_header const&);
	std::optional<data_header> header(std::uint64_t local_id) const;

	/// the rows whose header has the given content digest, ascending by id
	std::vector<data_state_row> find_by_content(octet_vector const& content_digest) const;

	void remove(std::uint64_t local_id);

	/// a transaction over the connection, for writes that belong together
	database::transaction transaction();

private:
	database::connection_ptr db_;
};

}
