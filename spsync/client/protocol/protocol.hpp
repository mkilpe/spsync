#pragma once

#include "types.hpp"

#include <securepath/util/typelist.hpp>

namespace securepath::sync::client::protocol {
inline namespace v1 {

std::uint16_t const current_version{1};

struct contacting {
	contacting() = default;
	contacting(std::string tag, host_port server, octet_vector data)
	: tag(std::move(tag))
	, sender_server(std::move(server))
	, data(std::move(data))
	{}

	std::uint16_t version{current_version};
	/// tag that can be used to identify which kind of contacting data is here
	std::string tag;
	/// Sender key server information, so that we can query the public key
	host_port sender_server;
	/// Arbitrary data associated with the contacting
	octet_vector data;
	serialisation::trailing_data trailing;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version & tag & sender_server & data & trailing;
	}
};

struct chat_invite {
	std::uint16_t version{current_version};

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version;
	}
};


using serialisation::type_tag;
using types =
	typelist<type_tag<contacting, 1>,
			 type_tag<chat_invite, 2>>;

}
}