// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint>

namespace securepath::sync {

/**
 * modes for synchronisation (server rules):
 *	- allow all at any time
 *	- require all up-to-date always
 */
enum class sync_mode : std::int64_t {
	allow_all,
    require_special_seen,
    require_data_add_remove_seen,
	require_all_seen
};

enum class auth_mode : std::int64_t {
    only_tag,
    sign_records
};

/// how a storage is replicated between servers (plan phases 3+); part of the immutable modes
enum class replication_mode : std::int64_t {
	none = 0,
	weak,
	strict
};

/**
 * Validity limits of a storage (record_data.txt RD10, RDS 8): whatever makes a record
 * invalid must be judged identically by every replica, so the limits are creation
 * parameters next to the modes - persisted, immutable, replicated. 0 = not stated: the
 * server default at creation, "whatever the storage has" when a client states its
 * expectation. Sizes in bytes.
 */
struct storage_limits {
	bool operator==(storage_limits const&) const = default;

public:
	/// the authenticated record content (chain_block::record_bytes); the signature and
	/// the chain framing (a few KiB) come on top on the wire
	std::uint32_t max_record_size{};
	/// the chunk size out of band data of this storage is cut into (RD3)
	std::uint32_t chunk_size{};
	/// retention at a history cut (RD9): how many of the newest data carrying versions of
	/// an object below the cut keep their data; keep_all_data_versions = every one
	std::uint32_t kept_data_versions{};
};

/// the values a limit of a storage may be set to
struct limit_range {
	[[nodiscard]] constexpr bool contains(std::uint32_t value) const {
		return value >= lowest && value <= highest;
	}

public:
	std::uint32_t lowest{};
	std::uint32_t highest{};
};

/**
 * The records that grow are the ones that scale with the group, not with a payload: a
 * user change carries the group key enveloped for every recipient (about 1.3 KB each, so
 * the 1 MiB default is a key rotation for about 800 members) and a segment record the tag
 * of every record it covers (18 B each, about 58000 records). The highest value is what
 * the DER codec takes for one octet string, which is what a record is inside its block
 * (checked where chain_block is defined): about 1600 members per key rotation and 116000
 * records per segment; more needs another record design, see doc/user_changes.txt.
 */
inline constexpr limit_range max_record_size_range{4 * 1024, 2 * 1024 * 1024};
std::uint32_t constexpr default_max_record_size{1024 * 1024};

/// the chunk is the unit at rest (one file, one AES-GCM pass); on the wire it travels in
/// pieces (protocol/data_protocol.hpp), so its size is not bound by a packet
inline constexpr limit_range chunk_size_range{256 * 1024, 8 * 1024 * 1024};
std::uint32_t constexpr default_chunk_size{1024 * 1024};

/**
 * Not a validity rule like the two above - what a cut keeps never makes a record invalid -
 * but a property of the storage all the same: replicas and clients cut alike, and members
 * know what to expect of old versions. The records of superseded versions always stay (the
 * chain needs them), only their data goes. The default keeps the newest version only.
 */
std::uint32_t constexpr keep_all_data_versions{0xFFFFFFFF};
inline constexpr limit_range kept_data_versions_range{1, keep_all_data_versions};
std::uint32_t constexpr default_kept_data_versions{1};

inline constexpr storage_limits default_storage_limits{default_max_record_size, default_chunk_size, default_kept_data_versions};

/// stated limits must be within the ranges; 0 = not stated
[[nodiscard]] constexpr bool valid_storage_limits(storage_limits const& l) {
	bool const record_ok = l.max_record_size == 0 || max_record_size_range.contains(l.max_record_size);
	bool const chunk_ok = l.chunk_size == 0 || chunk_size_range.contains(l.chunk_size);
	bool const kept_ok = l.kept_data_versions == 0 || kept_data_versions_range.contains(l.kept_data_versions);
	return record_ok && chunk_ok && kept_ok;
}

/// the stated limits with every unstated one taken from the others
[[nodiscard]] constexpr storage_limits limits_or(storage_limits stated, storage_limits const& others) {
	if(stated.max_record_size == 0) {
		stated.max_record_size = others.max_record_size;
	}
	if(stated.chunk_size == 0) {
		stated.chunk_size = others.chunk_size;
	}
	if(stated.kept_data_versions == 0) {
		stated.kept_data_versions = others.kept_data_versions;
	}
	return stated;
}

/// The modes a storage operates in; chosen at creation time and immutable afterwards
struct storage_modes {
	sync_mode mode{sync_mode::require_all_seen};
	auth_mode auth{auth_mode::only_tag};
	replication_mode replication{replication_mode::none};
	storage_limits limits{};

	bool operator==(storage_modes const&) const = default;
};

/**
 * A replicated storage requires signed records (plan 2.4/D5): a replica must be able to
 * verify what a peer sends without the group key. Stated limits must be in range.
 */
[[nodiscard]] constexpr bool valid_storage_modes(storage_modes const& m) {
	return (m.replication == replication_mode::none || m.auth == auth_mode::sign_records)
		&& valid_storage_limits(m.limits);
}

/**
 * The stated modes against the actual ones: a client states the sync and auth modes it
 * operates in, whether the server replicates the storage and which limits it created it
 * with are not things it has to know (replication none and limits 0 = not stated)
 */
[[nodiscard]] constexpr bool modes_match(storage_modes stated, storage_modes const& actual) {
	if(stated.replication == replication_mode::none) {
		stated.replication = actual.replication;
	}
	stated.limits = limits_or(stated.limits, actual.limits);
	return stated == actual;
}

}
