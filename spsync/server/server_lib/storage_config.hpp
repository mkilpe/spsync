#pragma once

#include <spsync/core/sync_mode.hpp>

#include <securepath/crypto/public_key_id.hpp>

#include <string>
#include <vector>

namespace securepath::sync {

/// Configuration options for storages
class storage_config {
public:
	storage_config() = default;
	explicit storage_config(std::string root, std::vector<crypto::public_key_id> peers = {})
	: storage_root_path_(std::move(root))
	, peers_(std::move(peers))
	{}

	/// Return root path of the record storage specific files like database
	std::string storage_root_path() const { return storage_root_path_; }

	/**
	 * Key ids of the known server peers that replicate this storage (plan 3.3); empty
	 * means every known peer. Resolved against the server peer list with
	 * replicating_peers() (see peer_config.hpp).
	 */
	std::vector<crypto::public_key_id> const& peers() const { return peers_; }

	/// the limits a storage created without stated limits gets (record_data.txt RD10);
	/// the server operator's defaults for new storages
	storage_limits const& default_limits() const { return default_limits_; }
	void set_default_limits(storage_limits const& l) { default_limits_ = l; }

private:
	// Path where the storages are located on the disk, can be relative or absolute
	std::string storage_root_path_ = "record-storages";
	std::vector<crypto::public_key_id> peers_;
	storage_limits default_limits_{default_storage_limits};
};

}

