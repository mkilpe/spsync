#ifndef SPSYNC_SERVER_STORAGE_SERVER_HEADER
#define SPSYNC_SERVER_STORAGE_SERVER_HEADER

#include <securepath/network/encryption/context.hpp>

#include <cstdint>
#include <memory>

namespace securepath::sync {

//t: move this to some place else
std::uint16_t const default_storage_server_port{18200};

struct storage_server_params {
	std::uint16_t storage_server_port{default_storage_server_port};

	/// this will override the above port if set
	std::optional<asio::ip::tcp::endpoint> storage_server_endpoint;

	asio::ip::tcp::endpoint create_storage_server_endpoint() const;
};

class storage_server {
public:
	storage_server(network::context, storage_server_params = {});
	~storage_server();

	void start();
	void close();
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif
