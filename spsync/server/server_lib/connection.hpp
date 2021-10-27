#ifndef SPSYNC_SERVER_CONNECTION_HEADER
#define SPSYNC_SERVER_CONNECTION_HEADER

#include "storage_server_context.hpp"

#include <spsync/protocol/client_protocol.hpp>
#include <securepath/crypto/public_key_id.hpp>

namespace securepath::sync {

//t: change the direct mutex locking scheme used in storage.cpp to event queue based mechanism to synchronise calls

class connection : public std::enable_shared_from_this<connection> {
public:
	connection(storage_server_context&);
	virtual ~connection() = default;

	securepath::error on_connect(protocol::client_hello const& p, crypto::public_key_id id);

	// the client_hello is handled in storage_server.cpp
	void handle(protocol::create_storage const&);
	void handle(protocol::destroy_storage const&);
	void handle(protocol::storage_management const&);
	void handle(protocol::request_sequence_number const&);
	void handle(protocol::request_records const&);
	void handle(protocol::request_data const&);
	void handle(protocol::request_commit const&);

	void notify(protocol::storage_id const& sid, chain_block const&);

private:
	virtual void send(octet_span s) = 0;
	template<typename T> void send_packet(T const& p);

	storage* find_storage(protocol::storage_id const&);
private:
	storage_server_context& context_;
	crypto::public_key_id id_;
	std::map<protocol::storage_id, std::shared_ptr<storage>> syncs_;
};

}

#endif
