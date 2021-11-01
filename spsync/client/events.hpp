#pragma once

#include "types.hpp"

namespace securepath::sync::client::events {

struct on_connect {
	typedef void type();
};

struct on_disconnect {
	typedef void type(error);
};

struct on_contacting {
	typedef void type(crypto::public_key_id sender, std::string tag, octet_vector data);
};

struct on_invitation {
	typedef void type();
};

}
