#include "request.hpp"

namespace securepath::sync::client {

std::string const arr[] =
	{
		"waiting_for_verification",
		"verification_succeeded",
		"verification_failed",
		"no_key_found",
		"cancelled"
	};

std::string to_string(request_state s) {
	if(int(s) >= 0 && s < request_state::end_of_list) {
		return arr[int(s)];
	}
	return "unknown";
}

}
