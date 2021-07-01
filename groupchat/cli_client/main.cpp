
#include <securepath/version.hpp>
#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/command_parser.hpp>

#include <iostream>

namespace securepath::groupchat {
namespace {

struct gc_cli_commands : command_parser {
	bool help{};

	gc_cli_commands() {
		add(help, "help", "h", "show help");
	}
};

}
}
/*
	sti_context_.set_mode(sti::mode::cbreak | sti::mode::noecho | sti::mode::colours);
	assert(has_colors());
	assert(sti::make_colour_pair(sti::colour_index{1}, sti::colour::white, sti::colour::blue));
	auto p = std::make_shared<sti::input_line>(sti::point{0, 1}, 10);
	p->set_attr(sti::attr{sti::colour_index{1}});

	sti_context_.add_widget(std::make_shared<sti::label>(sti::point{0, 0}, 10, L"0123456789"));
	sti_context_.add_widget(p);
	sti_context_.set_focus(p);
	sti_context_.thread_entry();
*/

int main(int argc, char* args[]) {
	int ret = -1;
	try {
		using namespace securepath;
		log::backend::add_backend<log::backend::file_output>("file", "gc-cli.log");

		gc_cli_commands p;
		p.parse(argc, args);

		if(p.help) {
			p.print_help(std::cout);
		} else {
			//cli::cli program;
			//program.run();
		}
	} catch(std::exception const& ex) {
		LOG_WARN("Error: %", ex.what());
		std::cerr << "Error: " << ex.what() << std::endl;
	}
	return ret;
}