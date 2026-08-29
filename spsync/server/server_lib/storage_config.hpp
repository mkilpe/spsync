#pragma once

#include <string>

namespace securepath::sync {

/// Configuration options for storages
class storage_config {
public:
	storage_config() = default;
	explicit storage_config(std::string root)
	: storage_root_path_(std::move(root))
	{}

	/// Return root path of the record storage specific files like database
	std::string storage_root_path() const { return storage_root_path_; }

private:
	// Path where the storages are located on the disk, can be relative or absolute
	std::string storage_root_path_ = "record-storages";
};

}

