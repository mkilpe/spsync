#pragma once

#include "types.hpp"
#include "request.hpp"

namespace securepath::sync::client::events {

/////
struct on_connect {
	typedef void type();
};

struct on_disconnect {
	typedef void type(error);
};

struct on_request {
	typedef void type(request);
};

struct on_contacting {
	typedef void type(request, std::string name, std::string message);
};

}
