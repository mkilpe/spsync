#ifndef SPSYNC_SERVER_CONNECTION_HEADER
#define SPSYNC_SERVER_CONNECTION_HEADER

#include <spsync/protocol/client_protocol.hpp>

#include <securepath/crypto/public_key_id.hpp>

namespace securepath::sync {

class connection {
public:
	connection() = default;
	virtual ~connection() = default;

	void on_connect(crypto::public_key_id id);

	void handle(protocol::create_storage const&);
	void handle(protocol::destroy_storage const&);
	void handle(protocol::storage_management const&);
	void handle(protocol::request_sequence_number const&);
	void handle(protocol::request_records const&);
	void handle(protocol::request_data const&);
	void handle(protocol::request_commit const&);

private:
	virtual void send(octet_span s) = 0;
	template<typename T>
	void send(T const& p);
private:
	crypto::public_key_id id_;
};

}

#endif
