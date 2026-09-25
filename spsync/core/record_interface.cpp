// SPDX-License-Identifier: MIT

#include "record_interface.hpp"

#include <ostream>

namespace securepath::sync {

bool is_valid_state(record_state state) {
	return record_state::invalid < state;
}

char const* const state_name[] = {"unknown",  "invalid", "pending commit", "pending sync", "in sync", "acked"};

std::string to_string(record_state state) {
	auto state_value = static_cast<std::size_t>(state);
	if(state_value < sizeof(state_name)/sizeof(*state_name)) {
		return state_name[state_value];
	}
	LOG_WARN("bad state value: {}", state_value);
	return "<bad state value>";
}

std::ostream& operator<<(std::ostream& out, record_state state) {
	return out << to_string(state);
}

}