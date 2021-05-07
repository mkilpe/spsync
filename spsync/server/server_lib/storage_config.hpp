#ifndef SPSYNC_SERVER_STORAGE_CONFIG_HEADER
#define SPSYNC_SERVER_STORAGE_CONFIG_HEADER

namespace securepath::sync {

/// Configuration options for storages
class storage_config {
public:

	/// Return root path of the record storage specific files like database
	std::string storage_root_path() const { return storage_root_path_; }

private:
	// Path where the storages are located on the disk, can be relative or absolute
	std::string storage_root_path_ = "record-storages";
};

}

#endif
