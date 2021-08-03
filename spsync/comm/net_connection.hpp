#ifndef SPSYNC_COMM_NET_CONNECTION_HEADER
#define SPSYNC_COMM_NET_CONNECTION_HEADER

#include <spsync/comm/interface.hpp>
#include <securepath/network/encryption/context.hpp>
#include <securepath/event_system/event_loop.hpp>

#include <memory>

namespace securepath::sync {

using storage_id = octet_vector;
class network_connection_impl;

/**
 * Helper to connect input and output of storage to the network connection
 * Use network_connection.create_storage_connection to construct one
 */
class storage_connection {
public:
	storage_connection(storage_id id, network_connection_impl& nc, comm_input& ci);

	/// attach output to the storage connection, after this network events are received
	void attach(comm_output&);

	/// the input for sync engine
	comm_input& input() const;
private:
	storage_id id_;
	network_connection_impl& nconn_;
	comm_input& input_;
};

namespace events {

/// emitted when connection is established
struct on_connect {
	using type = void();
};

/// emitted when connection is disconnected
struct on_disconnect {
	using type = void(error);
};

/// called as response to create_storage
struct on_create_storage {
	using type = void(storage_id, error);
};

}

/**
 * The network connection implementation between client and server
 */
class network_connection {
public:
	network_connection(network::context& context, event_system::event_handler& handler);
	~network_connection();

	/// Connect this network connection to server
	void connect(std::string_view host, std::uint16_t port);
	void close();

	/// Create storage on the server, one should wait for the on_create_storage event to see if the network call succeeded
	storage_id create_storage();
	void destroy_storage(storage_id const&);

	/// Create storage connection, returns storage connection helper. Nothing is received before the attach on the returned object is called.
	storage_connection create_storage_connection(storage_id, record_storage&, sync::progress&);

	// This will destroy the underlying comm_input, so make sure nothing is using it any more when this called
	void detach(storage_id const& id);

private:
	std::unique_ptr<network_connection_impl> impl_;
};

}

#endif
