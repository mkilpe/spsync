#pragma once

#include <string>
#include <vector>

namespace securepath::groupchat {

struct gc_cli_config {
	std::string path;
	/// DER file of the root public key anchoring the servers' certificate chains
	std::string root;
	/// the home server used when creating an account (defaults: gc.securepath.fi, default ports)
	std::string server;
	int keyport{};
	int syncport{};
	int packetport{};
	/// replicas of the home sync server as host:syncport[:keyport] (plan 4.5); given with an
	/// existing account they replace the stored ones
	std::vector<std::string> fallbacks;
};

}
