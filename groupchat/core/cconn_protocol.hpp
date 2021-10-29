#pragma once

#include "types.hpp"

#include <securepath/util/typelist.hpp>


namespace securepath::groupchat::protocol {
inline namespace v1 {

std::uint16_t const current_version{1};

struct contacting {
	contacting(std::string name = {}, host_port server = {})
	: sender_name(std::move(name))
	, sender_key_server(std::move(server))
	{}

	std::uint16_t version{current_version};
	std::string sender_name;
	host_port sender_key_server;
	serialisation::trailing_data trailing;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & version & sender_name & sender_key_server & trailing;
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
