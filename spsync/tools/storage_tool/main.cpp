
#include <spsync/core/record_storage.hpp>

#include <securepath/version.hpp>
#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/command_parser.hpp>

#include <filesystem>
#include <iostream>

namespace securepath::sync {
namespace {

struct storage_tool : command_parser {
	bool help{};
	bool verbose{};
	bool show_pending{};
	std::string storage;

	storage_tool() {
		add(help, "help", "h", "show help");
		add(verbose, "verbose", "v", "verbose mode");
		add(storage, "storage", "s", "storage database");
		add(show_pending, "pending", "", "show pending records");
	}

	void run() {
		if(!storage.empty()) {
			if(!std::filesystem::exists(storage)) {
				throw std::runtime_error("file does not exist: " + storage);
			}
			record_storage records(database::sqlite::create_sqlite_connection(storage));
			list_records(records);
		}
	}

	void list_records(record_storage const& records) {
		sequence_number last_sequence = records.last_block().sequence;
		if(last_sequence.is_valid()) {
			std::cout << "Storage has records [1, " << last_sequence.value << "]\n\n";
			for(sequence_number seq{1}; seq != last_sequence+1; ++seq) {
				auto h = records.find(seq);
				if(h) {
					std::cout << "\t" << seq.value << ": " << to_hex(h->tag()) << "\n";
				} else {
					std::cout << "\t" << seq.value << ": <no such record>\n";
				}
			}
			std::cout << std::endl;
		}
	}
};

}
}

int main(int argc, char* args[]) {
	try {
		securepath::sync::storage_tool p;
		p.parse(argc, args);
		if(p.help) {
			std::cout << "SPSync Storage Tool (using library version " << securepath::library_version() << ")\n";
			p.print_help(std::cout);
		} else {
			p.run();
		}
	} catch(std::exception const& ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
	}
}