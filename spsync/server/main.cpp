
#include <securepath/version.hpp>
#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/command_parser.hpp>

#include "server_lib/spsync_server.hpp"

#include <iostream>

namespace securepath {
namespace {

struct spsync_server_commands : sync::spsync_server_params, command_parser {
	bool help{};
	bool verbose{};

	spsync_server_commands() {
		add(help, "help", "h", "show help");
		add(verbose, "verbose", "v", "verbose mode");
	}
};

}
}

int main(int argc, char* args[]) {
	int ret = -1;
	try {
		using namespace securepath;
		log::backend::add_backend<log::backend::file_output>("file", "spsync_server.log");

		spsync_server_commands p;
		p.parse(argc, args);
		if(p.help) {
			std::cout << "SPSync Server (using library version " << library_version() << ")\n";
			p.print_help(std::cout);
		} else {
			ret = sync::spsync_server(p).run_and_wait();
		}
	} catch(std::exception const& ex) {
		LOG_WARN("Error: %", ex.what());
		std::cerr << "Error: " << ex.what() << std::endl;
	}
	return ret;
}