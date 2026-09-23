#pragma once

#include "data_descriptor.hpp"

#include <filesystem>
#include <optional>
#include <string>

namespace securepath::sync {

/**
 * The chunk-file layout of a data store (RD5/RD6), the same on clients and data
 * servers: <root>/<hex data_id>/<chunk number, 8 hex digits>, one file per encrypted
 * chunk. Only the files live here; which chunks are held and what they belong to is
 * the bookkeeping of the data table. A chunk file is complete or absent: it is written
 * under a temporary name and renamed.
 *
 * A data created locally has no id before its last chunk exists (data_id is the
 * manifest digest), so its chunks are staged under <root>/.staging/<name> and the
 * directory is renamed once the id is known.
 */
class chunk_files {
public:
	explicit chunk_files(std::filesystem::path root);

	/// store one encrypted chunk, replacing a previous one
	void write(data_id const&, std::uint64_t chunk_no, octet_span encrypted);

	/// the encrypted chunk, nullopt when it is not held
	std::optional<octet_vector> read(data_id const&, std::uint64_t chunk_no) const;

	/// size octets of a held chunk from offset (a transfer moves a chunk in pieces);
	/// nullopt when the chunk is not held or the range is not inside it
	std::optional<octet_vector> read_piece(data_id const&, std::uint64_t chunk_no, std::uint64_t offset, std::size_t size) const;

	bool has(data_id const&, std::uint64_t chunk_no) const;

	/// octets of the chunk's file, nullopt when there is none
	std::optional<std::uint64_t> size(data_id const&, std::uint64_t chunk_no) const;

	/// drop one chunk; fine when it is not held
	void remove_chunk(data_id const&, std::uint64_t chunk_no);

	/// drop every chunk of the data; fine when nothing is held
	void remove(data_id const&);


	// -- staging of a data whose id is not known yet --

	/// open a staging area, returns its name
	std::string begin_staging();

	void write_staged(std::string const& stage, std::uint64_t chunk_no, octet_span encrypted);

	/// append to a staged chunk that arrives in pieces
	void append_staged(std::string const& stage, std::uint64_t chunk_no, octet_span piece);

	/// octets of a staged chunk's file, nullopt when there is none
	std::optional<std::uint64_t> staged_size(std::string const& stage, std::uint64_t chunk_no) const;

	/// one staged chunk becomes a chunk of the data, replacing a previous one; the staging area goes
	void adopt_staged_chunk(std::string const& stage, std::uint64_t chunk_no, data_id const&);

	/// the staged chunks become the chunks of the data; a data already held keeps its chunks
	void commit_staging(std::string const& stage, data_id const&);

	/// drop a staging area; fine when it does not exist
	void discard_staging(std::string const& stage);

	/// drop every staging area: what an interrupted creation left behind
	void clear_staging();

private:
	std::filesystem::path data_dir(data_id const&) const;
	std::filesystem::path stage_dir(std::string const& stage) const;

private:
	std::filesystem::path root_;
};

}
