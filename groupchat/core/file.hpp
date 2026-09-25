// SPDX-License-Identifier: MIT

#pragma once

#include "message.hpp"
#include "types.hpp"

#include <cstdint>
#include <string>

namespace securepath::groupchat {

/// a shared file is an object of the chat storage (shared_files.txt SF-D1)
using file_id = sync::util::object_id;

/**
 * What a shared file is doing here (shared_files.txt SF-D7), read off its record and its
 * data when listed: an own share is pending until the server confirmed the record,
 * sharing while the data goes up, shared after; another member's share is on the
 * server until fetched, fetching on the way, fetched when held; removed once the local
 * copy was let go; gone when the data is invalid or the server let it go.
 */
enum class file_state {
	pending,
	sharing,
	shared,
	on_server,
	fetching,
	fetched,
	removed,
	gone
};

/// the state as text
inline char const* file_state_name(file_state state) {
	switch(state) {
	case file_state::pending: return "pending";
	case file_state::sharing: return "sharing";
	case file_state::shared: return "shared";
	case file_state::on_server: return "on_server";
	case file_state::fetching: return "fetching";
	case file_state::fetched: return "fetched";
	case file_state::removed: return "removed";
	case file_state::gone: return "gone";
	}
	return "gone";
}

/// the entry a share carries in its record's metadata (gc_file_v1)
struct file_data {
	std::string name;
	std::string mime;
	std::uint64_t size{};
	time_point shared_time;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & name & mime & size & shared_time;
	}
};

/// a file of the chat as the list shows it
struct file_entry {
	file_id id;
	std::string name;
	std::string mime;
	std::uint64_t size{};
	user_id sharer;
	time_point shared_time;
	index_type index{};
	file_state state{};
};

/// a search over the file list: the message search shape (index or time order, chunking)
using file_search = message_search;

/// where an insert put a file in the list and where it was while pending (0 when it was not)
struct file_change {
	index_type new_index{};
	index_type old_index{};
	file_id id;
	bool pending{};
};

}
