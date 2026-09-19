#pragma once

#include <spsync/core/record_data.hpp>

#include <filesystem>
#include <fstream>
#include <mutex>

namespace securepath::sync {

/**
 * Record data sources for engine_input::sync_object_change: the engine streams a source
 * once into the data store (RD7), it never becomes the stored data itself. A source
 * has no local id and no transfer state.
 */
class source_record_data : public record_data {
public:
	std::uint64_t local_id() const override { return 0; }
	std::uint64_t available_size() const override { return size(); }
	record_data_state state() const override { return record_data_state::unknown; }
	void set_state(record_data_state) override {}
	void remove_data() override {}
};

/// a source held in memory
class memory_record_data : public source_record_data {
public:
	memory_record_data() = default;
	explicit memory_record_data(octet_vector bytes);

	std::uint64_t size() const override;
	std::uint64_t read(std::uint64_t offset, std::uint8_t* buffer, std::uint64_t size) override;

	/// writes at or before the end, the data grows as needed; a write past the end writes nothing
	std::uint64_t write(std::uint64_t offset, std::uint8_t const* buffer, std::uint64_t size) override;

private:
	mutable std::mutex mutex_;
	octet_vector bytes_;
};

/// a file as a read-only source; the size is the file's size when the source was made
class file_record_data : public source_record_data {
public:
	explicit file_record_data(std::filesystem::path const&);

	std::uint64_t size() const override { return size_; }
	std::uint64_t read(std::uint64_t offset, std::uint8_t* buffer, std::uint64_t size) override;
	std::uint64_t write(std::uint64_t offset, std::uint8_t const* buffer, std::uint64_t size) override;

private:
	std::mutex mutex_;
	std::ifstream file_;
	std::uint64_t size_{};
};

}
