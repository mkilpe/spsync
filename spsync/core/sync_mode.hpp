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

/// The mode pair a storage operates in; chosen at creation time and immutable afterwards
struct storage_modes {
	sync_mode mode{sync_mode::require_all_seen};
	auth_mode auth{auth_mode::only_tag};

	bool operator==(storage_modes const&) const = default;
};

/// wire encoding for (optional) modes in protocol packets: 0 = not set, otherwise enum value + 1
inline std::uint32_t to_wire(sync_mode m) { return static_cast<std::uint32_t>(m) + 1; }
inline std::uint32_t to_wire(auth_mode m) { return static_cast<std::uint32_t>(m) + 1; }

inline std::pair<std::uint32_t, std::uint32_t> to_wire(std::optional<storage_modes> const& m) {
	return m ? std::pair{to_wire(m->mode), to_wire(m->auth)} : std::pair<std::uint32_t, std::uint32_t>{0, 0};
}

inline std::optional<storage_modes> modes_from_wire(std::uint32_t mode, std::uint32_t amode) {
	std::optional<storage_modes> ret;
	if(mode && amode
		&& mode-1 <= static_cast<std::uint32_t>(sync_mode::require_all_seen)
		&& amode-1 <= static_cast<std::uint32_t>(auth_mode::sign_records))
	{
		ret = storage_modes{sync_mode(mode-1), auth_mode(amode-1)};
	}
	return ret;
}

}
