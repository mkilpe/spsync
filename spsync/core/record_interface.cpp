#include "record_interface.hpp"

#include <ostream>

namespace securepath::sync {

bool is_valid_state(record_state state) {
	return record_state::invalid < state;
}

char const* const state_name[] = {"unknown",  "invalid", "pending commit", "pending sync", "in sync"};

std::ostream& operator<<(std::ostream& out, record_state state) {
	int state_value = static_cast<int>(state);
	if(0 <= state_value && state_value < sizeof(state_name)/sizeof(*state_name)) {
		out << state_name[state_value];
	} else {
		LOG_WARN("bad state value: %", state_value);
		out << "<bad state value>";
	}
	return out;
}

}