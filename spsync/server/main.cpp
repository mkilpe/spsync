
#include <securepath/version.hpp>
#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/log/log.hpp>
#include <securepath/util/command_parser.hpp>

#include "server_lib/spsync_server.hpp"

#include <filesystem>
#include <format>
#include <iostream>

namespace securepath {
namespace {

struct spsync_server_commands : sync::spsync_server_params, command_parser {
	bool help{};
	bool verbose{};
	int timeout{};
	int anti_entropy{};
	int upload_expiry{};
	int ticket_validity{};
	int transfer_window{};

	spsync_server_commands() {
		add(help, "help", "h", "show help");
		add(verbose, "verbose", "v", "verbose mode");
		add(timeout, "timeout", "", "Connecting/Handshake timeout in seconds");
		add(key_params.root_public_key_file, "root", "", "DER file of the root public key anchoring certificate chains");
		add(key_params.port, "key_port", "", "key server listening port");
		add(storage_params.storage_server_port, "storage_port", "", "storage server listening port");
		add(storage_params.s2s_port, "s2s_port", "", "server-to-server listening port (used when peers are configured)");
		add(storage_params.storage_root, "storage_root", "", "directory of the record storages");
		add(storage_params.server_id, "server_id", "", "expected public key id (hex) of the storage server key");
		add(storage_params.peers, "peers", "", "replication peers as host:port/keyid-hex");
		add(anti_entropy, "anti_entropy", "", "seconds between replicated head announcements to the peers");
		add(storage_params.default_limits.max_record_size, "max_record_size", "", "default record content limit (bytes) of new storages");
		add(storage_params.default_limits.chunk_size, "chunk_size", "", "default data chunk size (bytes) of new storages");
		add(storage_params.data_servers, "data_servers", "", "data-role servers of the storages as host:port/keyid-hex[/region]; an all-in-one server lists itself");
		add(ticket_validity, "ticket_validity", "", "seconds an issued data ticket is valid");
		add(data_params.enabled, "data_role", "", "serve record data: run the data listener");
		add(data_params.data_port, "data_port", "", "data server listening port");
		add(data_params.record_servers, "record_servers", "", "record servers of the data role as host:s2s_port/keyid-hex: their data tickets are accepted and they are told what is held; the own key always is accepted");
		add(data_params.quota.max_data_size, "max_data_size", "", "biggest single record data (encrypted bytes) this server takes, 0 = no limit");
		add(data_params.quota.max_storage_bytes, "max_storage_data", "", "record data bytes one storage may take on this server, 0 = no limit");
		add(upload_expiry, "upload_expiry", "", "seconds after which an untouched incomplete upload is dropped");
		add(data_params.transfer.bytes_per_window, "transfer_quota", "", "record data bytes served per storage and window, 0 = no limit");
		add(transfer_window, "transfer_window", "", "seconds of a transfer quota window");
	}

	void handle_inputs() {
		if(timeout) {
			key_params.timeout = std::chrono::seconds(timeout);
			storage_params.timeout = std::chrono::seconds(timeout);
		}
		if(anti_entropy) {
			storage_params.anti_entropy_interval = std::chrono::seconds(anti_entropy);
		}
		if(timeout) {
			data_params.timeout = std::chrono::seconds(timeout);
		}
		if(ticket_validity) {
			storage_params.ticket_validity = std::chrono::seconds(ticket_validity);
		}
		if(transfer_window) {
			data_params.transfer.window = std::chrono::seconds(transfer_window);
		}
		if(upload_expiry) {
			data_params.incomplete_upload_expiry = std::chrono::seconds(upload_expiry);
		}
		// the data of a storage lives next to its records
		data_params.storage_root = storage_params.storage_root;
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
		if(std::filesystem::exists("spsync_server.cfg")) {
			LOG_TRACE("using config file 'spsync_server.cfg'");
			p.parse_file("spsync_server.cfg");
		}
		p.parse(argc, args);
		if(p.help) {
			std::cout << "SPSync Server (using library version " << library_version() << ")\n";
			p.print_help(std::cout);
		} else {
			p.handle_inputs();
			ret = sync::spsync_server(p).run_and_wait();
		}
	} catch(securepath::error const& err) {
		LOG_WARN("Error={}", err);
		std::cerr << std::format("Error={}", err) << std::endl;
	} catch(std::exception const& ex) {
		LOG_WARN("Error={}", ex.what());
		std::cerr << "Error=" << ex.what() << std::endl;
	}
	return ret;
}