// SPDX-License-Identifier: MIT

#pragma once

#include "data_store.hpp"

#include <spsync/protocol/data_protocol.hpp>

#include <securepath/crypto/public_key_access.hpp>
#include <securepath/crypto/public_key_id.hpp>

#include <chrono>
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

	/// a client said hello: whether it may have this session (a cap per key), and when
	/// it is gone (once per admitted session)
	virtual bool admit(crypto::public_key_id const&) = 0;
	virtual void leave(crypto::public_key_id const&) = 0;

	virtual time_point now() const = 0;
};

/// what one connection may have on its way at once
struct data_connection_limits {
	/// uploads and downloads opened on the connection, each; the least recently used goes
	/// when one more is opened
	std::size_t max_transfers{256};
	/// octets of half received chunks staged for the connection's uploads
	std::uint64_t max_staged_bytes{256 * 1024 * 1024};
	/// a transfer nothing moved on for this long is dropped (its staged pieces with it)
	std::chrono::seconds transfer_idle_limit{600};
};

/**
 * One client on the data listener (record_data.txt RD4/RD12), transport left out: the
 * uploads and downloads the client opened with a ticket and the pieces that move for
 * them. Every transfer starts with a ticket that must be signed by a trusted record
 * server, unexpired, for the right direction, and issued to the key this connection
 * authenticated with. What a connection may have open and staged is bounded
 * (data_connection_limits): a client that opens transfers and walks away does not keep
 * them for as long as the socket lives.
 */
class data_connection {
public:
	explicit data_connection(data_server_context&, data_connection_limits = {});
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
		/// by chunk number; dropped with the upload, the staged pieces with them
		std::map<std::uint64_t, incoming_chunk> incoming;
		time_point last_used;
	};

	/// one download a ticket opened on this connection: where it is served from, and
	/// whether it counts against the storage's transfer quota (a data server's copy does not)
	struct download {
		std::shared_ptr<server_data_store> store;
		bool charged{true};
		time_point last_used;
	};

	/// take one piece; true when it completed the data
	util::result<bool> take_piece(upload&, protocol::upload_data_chunk const&);

private:
	using upload_key = std::pair<protocol::storage_id, data_id>;

	/// chunks of one upload on their way in at once: more than any sender's window needs
	static constexpr std::size_t max_incoming_chunks{32};

	/// the transfers nothing moved on for the idle limit go, before every request
	void trim_idle(time_point now);
	/// room for one more transfer: the least recently used goes when the map is full
	template<typename Transfer>
	void make_room(std::map<upload_key, Transfer>&);
	/// octets the half received chunks of every upload of the connection may take
	std::uint64_t staged_bytes() const;

	data_server_context& context_;
	data_connection_limits const limits_;
	crypto::public_key_id id_;
	std::map<upload_key, upload> uploads_;
	std::map<upload_key, download> downloads_;
};

}
