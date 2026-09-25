// SPDX-License-Identifier: MIT

#pragma once

#include <spsync/core/sync_mode.hpp>

#include <securepath/serialisation/sequence.hpp>

#include <cstdint>
#include <optional>

/**
 * The storage modes as they travel in packets: an optional set of modes is three
 * enum values shifted by one (0 = not stated) and the limits as plain values (0 = not
 * stated). The modes themselves and their rules are core's (core/sync_mode.hpp); the
 * wire form is the protocol's (review 2026-09-24 R2).
 */
namespace securepath::sync::protocol {

/// wire encoding for (optional) modes in protocol packets: 0 = not set, otherwise enum value + 1
inline std::uint32_t to_wire(sync_mode m) { return static_cast<std::uint32_t>(m) + 1; }
inline std::uint32_t to_wire(auth_mode m) { return static_cast<std::uint32_t>(m) + 1; }
inline std::uint32_t to_wire(replication_mode m) { return static_cast<std::uint32_t>(m) + 1; }

struct wire_modes {
	/// the stated limits (0 = not stated)
	storage_limits limits() const { return storage_limits{max_record_size, chunk_size, kept_data_versions}; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & mode & amode & repl & max_record_size & chunk_size & kept_data_versions;
	}

public:
	std::uint32_t mode{};
	std::uint32_t amode{};
	std::uint32_t repl{};
	/// the limits travel as plain values (0 = not stated)
	std::uint32_t max_record_size{};
	std::uint32_t chunk_size{};
	std::uint32_t kept_data_versions{};
};

inline wire_modes to_wire(std::optional<storage_modes> const& m) {
	return m ? wire_modes{to_wire(m->mode), to_wire(m->auth), to_wire(m->replication),
		m->limits.max_record_size, m->limits.chunk_size, m->limits.kept_data_versions} : wire_modes{};
}

inline std::optional<storage_modes> modes_from_wire(std::uint32_t mode, std::uint32_t amode,
	std::uint32_t repl = to_wire(replication_mode::none), storage_limits const& limits = {})
{
	std::optional<storage_modes> ret;
	if(mode && amode && repl
		&& mode-1 <= static_cast<std::uint32_t>(sync_mode::require_all_seen)
		&& amode-1 <= static_cast<std::uint32_t>(auth_mode::sign_records)
		&& repl-1 <= static_cast<std::uint32_t>(replication_mode::strict))
	{
		ret = storage_modes{sync_mode(mode-1), auth_mode(amode-1), replication_mode(repl-1), limits};
	}
	return ret;
}

inline std::optional<storage_modes> modes_from_wire(wire_modes const& w) {
	return modes_from_wire(w.mode, w.amode, w.repl, w.limits());
}

}
