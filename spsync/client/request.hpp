#pragma once

#include "types.hpp"
#include <infrastructure/packet_transport/protocol/types.hpp>

namespace securepath::sync::client {

/*
	Request handling flow:
		* incoming request
		* notify
			* higher layer extracts the request data and lets user know
		* query key
		* verify authenticity
		* notify
			* higher layer extracts the request data and lets user know
		* wait for user action
		* remove
*/

/// request data stored in database
struct request_data {
	user sender;
	std::string tag;
	octet_vector data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & sender & tag & data;
	}
};

enum class request_state {
	waiting_for_verification = 0,
	verification_succeeded,
	querying_key_failed,
	verification_failed,
	no_key_found,
	cancelled,
	end_of_list
};

std::string to_string(request_state);

struct request : request_data {
	request_id id{};
	request_state state{request_state::waiting_for_verification};
};

struct db_request : request {
	// this is required to check the signature
	packet_transport::transport_payload payload;
};

}
