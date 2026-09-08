#include "request.hpp"

#include <iterator>

namespace securepath::sync::client {

std::string const arr[] =
	{
		"waiting_for_verification",
		"verification_succeeded",
		"querying_key_failed",
		"verification_failed",
		"no_key_found",
		"cancelled"
	};
static_assert(std::size(arr) == static_cast<std::size_t>(request_state::end_of_list), "request state names out of step");

std::string to_string(request_state s) {
	if(int(s) >= 0 && s < request_state::end_of_list) {
		return arr[int(s)];
	}
	return "unknown";
}

}
