#pragma once

#include <cstdint>
#include <optional>
#include <utility>

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
	/// the authenticated record content (chain_block::record_bytes); the signature and
	/// the chain framing (a few KiB) come on top on the wire
	std::uint32_t max_record_size{};
	/// the chunk size out of band data of this storage is cut into (RD3)
	std::uint32_t chunk_size{};

	bool operator==(storage_limits const&) const = default;
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

/// stated limits must be within the ranges; 0 = not stated
[[nodiscard]] constexpr bool valid_storage_limits(storage_limits const& l) {
	bool const record_ok = l.max_record_size == 0 || max_record_size_range.contains(l.max_record_size);
	bool const chunk_ok = l.chunk_size == 0 || chunk_size_range.contains(l.chunk_size);
	return record_ok && chunk_ok;
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
	if(stated.limits.max_record_size == 0) {
		stated.limits.max_record_size = actual.limits.max_record_size;
	}
	if(stated.limits.chunk_size == 0) {
		stated.limits.chunk_size = actual.limits.chunk_size;
	}
	return stated == actual;
}

/// wire encoding for (optional) modes in protocol packets: 0 = not set, otherwise enum value + 1
inline std::uint32_t to_wire(sync_mode m) { return static_cast<std::uint32_t>(m) + 1; }
inline std::uint32_t to_wire(auth_mode m) { return static_cast<std::uint32_t>(m) + 1; }
inline std::uint32_t to_wire(replication_mode m) { return static_cast<std::uint32_t>(m) + 1; }

struct wire_modes {
	std::uint32_t mode{};
	std::uint32_t amode{};
	std::uint32_t repl{};
	/// the limits travel as plain values (0 = not stated)
	std::uint32_t max_record_size{};
	std::uint32_t chunk_size{};
};

inline wire_modes to_wire(std::optional<storage_modes> const& m) {
	return m ? wire_modes{to_wire(m->mode), to_wire(m->auth), to_wire(m->replication),
		m->limits.max_record_size, m->limits.chunk_size} : wire_modes{};
}

inline std::optional<storage_modes> modes_from_wire(std::uint32_t mode, std::uint32_t amode,
	std::uint32_t repl = to_wire(replication_mode::none), std::uint32_t max_record_size = 0, std::uint32_t chunk_size = 0)
{
	std::optional<storage_modes> ret;
	if(mode && amode && repl
		&& mode-1 <= static_cast<std::uint32_t>(sync_mode::require_all_seen)
		&& amode-1 <= static_cast<std::uint32_t>(auth_mode::sign_records)
		&& repl-1 <= static_cast<std::uint32_t>(replication_mode::strict))
	{
		ret = storage_modes{sync_mode(mode-1), auth_mode(amode-1), replication_mode(repl-1),
			storage_limits{max_record_size, chunk_size}};
	}
	return ret;
}

inline std::optional<storage_modes> modes_from_wire(wire_modes const& w) {
	return modes_from_wire(w.mode, w.amode, w.repl, w.max_record_size, w.chunk_size);
}

}
