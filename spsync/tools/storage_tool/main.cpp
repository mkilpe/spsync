
#include <spsync/core/record_storage.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/util/command_parser.hpp>

#include <iostream>

namespace securepath::sync {
namespace {

struct storage_tool : command_parser {
	bool help{};
	bool verbose{};
	std::string storage;

	storage_tool() {
		add(help, "help", "h", "Show help");
		add(verbose, "verbose", "v", "verbose mode");
		add(storage, "storage", "s", "storage database");
	}

	void run() {
		if(!storage.empty()) {
			record_storage records(database::sqlite::create_sqlite_connection(storage));
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
	}
};

}
}

int main(int argc, char* args[]) {
	try {
		securepath::sync::storage_tool p;
		p.parse(argc, args);
		p.run();
	} catch(std::exception const& ex) {
		std::cerr << "Error: " << ex.what() << std::endl;
	}
}