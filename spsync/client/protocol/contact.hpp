#pragma once

#include <spsync/client/types.hpp>


namespace securepath::sync::client::protocol {
inline namespace v1 {

struct contact_data {

	std::string name;
	std::string message;
	serialisation::trailing_data trailing;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & name & message & trailing;
	}
};

}
}