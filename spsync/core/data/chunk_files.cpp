#include "chunk_files.hpp"

#include <securepath/crypto/random.hpp>
#include <securepath/util/conversions.hpp>
#include <securepath/util/error.hpp>

#include <algorithm>
#include <cctype>
#include <format>
#include <fstream>

namespace securepath::sync {
namespace {

char const* const staging_name = ".staging";

std::string chunk_name(std::uint64_t chunk_no) {
	return std::format("{:08x}", chunk_no);
}

error io_error(std::string msg) {
	return error(std::make_error_code(std::errc::io_error), std::move(msg));
}

/// the file is complete or absent: written under a temporary name and renamed
void write_file(std::filesystem::path const& dir, std::string const& name, octet_span bytes) {
	std::filesystem::create_directories(dir);
	auto const tmp = dir / (name + ".tmp");
	{
		std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
		out.write(reinterpret_cast<char const*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
		out.flush();
		if(!out) {
			throw io_error("failed to write chunk file " + tmp.string());
		}
	}
	std::filesystem::rename(tmp, dir / name);
}

std::optional<octet_vector> read_file(std::filesystem::path const& path) {
	std::optional<octet_vector> ret;
	std::error_code ec;
	auto const size = std::filesystem::file_size(path, ec);
	if(!ec) {
		std::ifstream in(path, std::ios::binary);
		octet_vector bytes(size);
		in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
		if(in && static_cast<std::uintmax_t>(in.gcount()) == size) {
			ret = std::move(bytes);
		}
	}
	return ret;
}

bool is_hex_name(std::string const& s) {
	return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

}

chunk_files::chunk_files(std::filesystem::path root)
: root_(std::move(root))
{
}

std::filesystem::path chunk_files::data_dir(data_id const& id) const {
	// an empty id would name the root itself
	if(id.empty()) {
		throw make_error(securepath::errc::invalid_argument, "empty record data id");
	}
	return root_ / to_hex(id);
}

std::filesystem::path chunk_files::stage_dir(std::string const& stage) const {
	if(!is_hex_name(stage)) {
		throw make_error(securepath::errc::invalid_argument, "invalid record data staging name");
	}
	return root_ / staging_name / stage;
}

void chunk_files::write(data_id const& id, std::uint64_t chunk_no, octet_span encrypted) {
	write_file(data_dir(id), chunk_name(chunk_no), encrypted);
}

std::optional<octet_vector> chunk_files::read(data_id const& id, std::uint64_t chunk_no) const {
	return read_file(data_dir(id) / chunk_name(chunk_no));
}

bool chunk_files::has(data_id const& id, std::uint64_t chunk_no) const {
	std::error_code ec;
	return std::filesystem::is_regular_file(data_dir(id) / chunk_name(chunk_no), ec);
}

void chunk_files::remove_chunk(data_id const& id, std::uint64_t chunk_no) {
	std::error_code ec;
	std::filesystem::remove(data_dir(id) / chunk_name(chunk_no), ec);
}

void chunk_files::remove(data_id const& id) {
	std::filesystem::remove_all(data_dir(id));
}

std::string chunk_files::begin_staging() {
	auto stage = to_hex(crypto::random_octet_vector(16));
	std::filesystem::create_directories(stage_dir(stage));
	return stage;
}

void chunk_files::write_staged(std::string const& stage, std::uint64_t chunk_no, octet_span encrypted) {
	write_file(stage_dir(stage), chunk_name(chunk_no), encrypted);
}

void chunk_files::commit_staging(std::string const& stage, data_id const& id) {
	auto const target = data_dir(id);
	auto const source = stage_dir(stage);
	if(std::filesystem::exists(target)) {
		// the same id is the same chunks: keep what is held
		std::filesystem::remove_all(source);
	} else {
		std::filesystem::rename(source, target);
	}
}

void chunk_files::discard_staging(std::string const& stage) {
	std::filesystem::remove_all(stage_dir(stage));
}

void chunk_files::clear_staging() {
	std::filesystem::remove_all(root_ / staging_name);
}

}
