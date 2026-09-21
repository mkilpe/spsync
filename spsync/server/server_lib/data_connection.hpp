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
 * uploads and downloads the client opened with a ticket and the pieces that move for
 * them. Every transfer starts with a ticket that must be signed by a trusted record
 * server, unexpired, for the right direction, and issued to the key this connection
 * authenticated with.
 */
class data_connection {
public:
	explicit data_connection(data_server_context&);
	virtual ~data_connection() = default;

	securepath::error on_connect(protocol::data_hello const&, crypto::public_key_id);

	void handle(protocol::upload_data_manifest const&);
	void handle(protocol::upload_data_chunk const&);
	void handle(protocol::download_data_open const&);
	void handle(protocol::download_data_piece const&);

private:
	virtual void send(octet_span s) = 0;
	template<typename T> void send_packet(T const& p);

	/// protocol error of a ticket this connection does not accept, no error when it does
	securepath::error check_ticket(data_ticket const&, data_right) const;
	/// the same for a download, which a member's ticket opens and a data server's
	securepath::error check_download_ticket(data_ticket const&) const;

	/// one upload a manifest opened on this connection and its chunks on their way in
	struct upload {
		std::shared_ptr<server_data_store> store;
		/// by chunk number; dropped with the connection, the staged pieces with them
		std::map<std::uint64_t, incoming_chunk> incoming;
	};

	/// take one piece; true when it completed the data
	util::result<bool> take_piece(upload&, protocol::upload_data_chunk const&);

private:
	using upload_key = std::pair<protocol::storage_id, data_id>;

	/// chunks of one upload on their way in at once: more than any sender's window needs
	static constexpr std::size_t max_incoming_chunks{32};

	data_server_context& context_;
	crypto::public_key_id id_;
	std::map<upload_key, upload> uploads_;
	/// the downloads a ticket opened on this connection
	/// an opened download: where it is served from, and whether it counts against the
	/// storage's transfer quota (a data server's copy does not)
	struct download {
		std::shared_ptr<server_data_store> store;
		bool charged{true};
	};
	std::map<upload_key, download> downloads_;
};

}
