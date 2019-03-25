
#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/log/log.hpp>

#include "server_lib/spsync_server.hpp"

#include <iostream>

int main(int argc, char* args[]) {
	int ret = -1;
	try {
		securepath::log::backend::add_backend<securepath::log::backend::file_output>("file", "spsync_server.log");
		ret = securepath::sync::spsync_server().run_and_wait();
	} catch(std::exception const& ex) {
		LOG_WARN("Error: %", ex.what());
		std::cerr << "Error: " << ex.what() << std::endl;
	}
	return ret;
}