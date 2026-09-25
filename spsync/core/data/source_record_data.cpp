// SPDX-License-Identifier: MIT

#include "source_record_data.hpp"

#include <spsync/core/error.hpp>

#include <algorithm>
#include <cstring>

namespace securepath::sync {

memory_record_data::memory_record_data(octet_vector bytes)
: bytes_(std::move(bytes))
{
}

std::uint64_t memory_record_data::size() const {
	std::unique_lock lock{mutex_};
	return bytes_.size();
}

std::uint64_t memory_record_data::read(std::uint64_t offset, std::uint8_t* buffer, std::uint64_t size) {
	std::unique_lock lock{mutex_};
	std::uint64_t n = 0;
	if(offset < bytes_.size()) {
		n = std::min<std::uint64_t>(size, bytes_.size() - offset);
		std::memcpy(buffer, bytes_.data() + offset, n);
	}
	return n;
}

std::uint64_t memory_record_data::write(std::uint64_t offset, std::uint8_t const* buffer, std::uint64_t size) {
	std::unique_lock lock{mutex_};
	std::uint64_t n = 0;
	if(offset <= bytes_.size() && size != 0) {
		if(offset + size > bytes_.size()) {
			bytes_.resize(offset + size);
		}
		std::memcpy(bytes_.data() + offset, buffer, size);
		n = size;
	}
	return n;
}

file_record_data::file_record_data(std::filesystem::path const& path)
: file_(path, std::ios::binary)
{
	if(!file_) {
		throw error(std::make_error_code(std::errc::no_such_file_or_directory), "failed to open record data source " + path.string());
	}
	size_ = std::filesystem::file_size(path);
}

std::uint64_t file_record_data::read(std::uint64_t offset, std::uint8_t* buffer, std::uint64_t size) {
	std::unique_lock lock{mutex_};
	std::uint64_t n = 0;
	if(offset < size_) {
		file_.clear();
		file_.seekg(static_cast<std::streamoff>(offset));
		file_.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(std::min<std::uint64_t>(size, size_ - offset)));
		n = static_cast<std::uint64_t>(file_.gcount());
	}
	return n;
}

std::uint64_t file_record_data::write(std::uint64_t, std::uint8_t const*, std::uint64_t) {
	throw make_error(sync::errc::constraint_violation, "a file record data source is read-only");
}

}
