#ifndef SPSYNC_SERVER_STORAGE_SERVER_HEADER
#define SPSYNC_SERVER_STORAGE_SERVER_HEADER

#include <securepath/network/encryption/context.hpp>
#include <spsync/protocol/ports.hpp>

#include <cstdint>
#include <memory>

using namespace std::chrono_literals;

namespace securepath::sync {

struct storage_server_params {
	std::uint16_t storage_server_port{default_storage_server_port};

	/// this will override the above port if set
	std::optional<asio::ip::tcp::endpoint> storage_server_endpoint;

	asio::ip::tcp::endpoint create_endpoint() const;

	/// connecting/handshake timeout
	std::chrono::seconds timeout{10s};
};

class storage_server {
public:
	storage_server(network::context&, storage_server_params = {});
	~storage_server();

	void start();
	void close();
private:
	class impl;
	// encrypted_server requires this to be shared_ptr
	std::shared_ptr<impl> impl_;
};

}

#endif
