#pragma once

#include "data_change_record.hpp"
#include "../error.hpp"

namespace securepath::sync {

inline single_change get_single_change(data_change_record const& r) {
	if(!r.is_single_change_record()) {
		throw error(errc::invalid_record_state, "expected single change record");
	}
	return *r.begin();
}

}

