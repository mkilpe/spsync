#pragma once

#include "data_store.hpp"

#include <spsync/protocol/data_protocol.hpp>

#include <securepath/crypto/public_key_access.hpp>
#include <securepath/crypto/public_key_id.hpp>

#include <map>
#include <memory>

namespace securepath::sync {

/// what a data connection needs from the data server around it
class data_server_context {
protected:
	~data_server_context() = default;

public:
	/// the data store of a storage, created when the storage is new to this server
	virtual std::shared_ptr<server_data_store> acquire_store(protocol::storage_id const&) = 0;

	/// the keys ticket signatures are verified with
	virtual crypto::public_key_access const& keys() const = 0;

	/// true for a record server this data server accepts tickets from (RD12)
	virtual bool trusted_issuer(crypto::public_key_id const&) const = 0;

	/// a data became complete here (RD13): the record servers are told
	virtual void announce_complete(protocol::storage_id const&, data_id const&) = 0;

	virtual time_point now() const = 0;
};

/**
 * One client on the data listener (record_data.txt RD4/RD12), transport left out: the
 * uploads the client opened with a ticket and the chunks it sends for them. Every upload
 * starts with a ticket that must be signed by a trusted record server, unexpired, for
 * uploading, and issued to the key this connection authenticated with.
 */
class data_connection {
public:
	explicit data_connection(data_server_context&);
	virtual ~data_connection() = default;

	securepath::error on_connect(protocol::data_hello const&, crypto::public_key_id);

	void handle(protocol::upload_data_manifest const&);
	void handle(protocol::upload_data_chunk const&);

private:
	virtual void send(octet_span s) = 0;
	template<typename T> void send_packet(T const& p);

	/// protocol error of a ticket this connection does not accept, no error when it does
	securepath::error check_ticket(data_ticket const&, data_right) const;

private:
	using upload_key = std::pair<protocol::storage_id, data_id>;

	data_server_context& context_;
	crypto::public_key_id id_;
	/// the uploads a manifest opened on this connection
	std::map<upload_key, std::shared_ptr<server_data_store>> uploads_;
};

}
