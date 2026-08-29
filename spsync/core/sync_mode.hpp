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
enum class sync_mode {
	allow_all,
    require_special_seen,
    require_data_add_remove_seen,
	require_all_seen
};

enum class auth_mode {
    only_tag,
    sign_records
};

/// how a storage is replicated between servers (plan phases 3+); part of the immutable modes
enum class replication_mode {
	none = 0,
	weak,
	strict
};

/// The modes a storage operates in; chosen at creation time and immutable afterwards
struct storage_modes {
	sync_mode mode{sync_mode::require_all_seen};
	auth_mode auth{auth_mode::only_tag};
	replication_mode replication{replication_mode::none};

	bool operator==(storage_modes const&) const = default;
};

/**
 * A replicated storage requires signed records (plan 2.4/D5): a replica must be able to
 * verify what a peer sends without the group key.
 */
constexpr bool valid_storage_modes(storage_modes const& m) {
	return m.replication == replication_mode::none || m.auth == auth_mode::sign_records;
}

/// wire encoding for (optional) modes in protocol packets: 0 = not set, otherwise enum value + 1
inline std::uint32_t to_wire(sync_mode m) { return static_cast<std::uint32_t>(m) + 1; }
inline std::uint32_t to_wire(auth_mode m) { return static_cast<std::uint32_t>(m) + 1; }
inline std::uint32_t to_wire(replication_mode m) { return static_cast<std::uint32_t>(m) + 1; }

struct wire_modes {
	std::uint32_t mode{};
	std::uint32_t amode{};
	std::uint32_t repl{};
};

inline wire_modes to_wire(std::optional<storage_modes> const& m) {
	return m ? wire_modes{to_wire(m->mode), to_wire(m->auth), to_wire(m->replication)} : wire_modes{};
}

inline std::optional<storage_modes> modes_from_wire(std::uint32_t mode, std::uint32_t amode, std::uint32_t repl = to_wire(replication_mode::none)) {
	std::optional<storage_modes> ret;
	if(mode && amode && repl
		&& mode-1 <= static_cast<std::uint32_t>(sync_mode::require_all_seen)
		&& amode-1 <= static_cast<std::uint32_t>(auth_mode::sign_records)
		&& repl-1 <= static_cast<std::uint32_t>(replication_mode::strict))
	{
		ret = storage_modes{sync_mode(mode-1), auth_mode(amode-1), replication_mode(repl-1)};
	}
	return ret;
}

}
