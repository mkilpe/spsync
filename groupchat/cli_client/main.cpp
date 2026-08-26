
#include "gc_cli.hpp"

#include <securepath/version.hpp>
#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/command_parser.hpp>

#include <iostream>

namespace securepath::groupchat {
namespace {

struct gc_cli_commands : gc_cli_config, command_parser {
	bool help{};

	gc_cli_commands() {
		add(help, "help", "h", "show help");
		add(path, "path", "p", "path to find gc_client.db");
	}
};

}
}

int main(int argc, char* args[]) {
	int ret = -1;
	try {
		using namespace securepath;
		using namespace securepath::groupchat;

		log::backend::add_backend<log::backend::file_output>("file", "gc_cli.log");

		gc_cli_commands p;
		p.parse(argc, args);

		if(p.help) {
			p.print_help(std::cout);
		} else {
			gc_cli program(p);
			program.run();
		}
	} catch(std::exception const& ex) {
		LOG_WARN("Error: {}", ex.what());
		std::cerr << "Error: " << ex.what() << std::endl;
	}
	return ret;
}