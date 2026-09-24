#pragma once

#include "storage_data_context.hpp"
#include "storage_server_context.hpp"

#include <spsync/core/origin_head.hpp>
#include <spsync/protocol/s2s_protocol.hpp>

#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/framing.hpp>
#include <securepath/serialisation/util.hpp>

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace securepath::sync {

/**
 * One server-to-server connection (plan 4.1), used for both directions: an outgoing
 * connection is dialed to a configured peer (connect_peer) and an incoming one is
 * accepted by the s2s listener. Both sides authenticate the remote ML-DSA key id
 * against the peer configuration (3.3), exchange peer_hello and then announce the
 * heads of their replicated storages. pull_records is served from the chain log;
 * push_records is applied with plan 4.2. A configured data server that is no peer is
 * accepted as well (record_data.txt RD12/RD13): its link carries data announcements only.
 */
class peer_connection : public network::encrypted_connection {
public:
	peer_connection(network::context&, storage_server_context&, storage_data_context&, network::handshake_data,
		std::shared_ptr<network::encrypted_server> server = nullptr);
	~peer_connection();

	/// dial the configured peer; the transport key must match the peer's key id
	void connect_peer(peer_config const& peer, std::chrono::seconds timeout);

	/// the authenticated peer id, set once peer_hello was verified
	std::optional<crypto::public_key_id> peer_id() const;

	/// the last heads the peer announced for the storage (anti-entropy input, plan 4.4)
	std::vector<origin_head> heads_of_peer(protocol::storage_id const&) const;

	/// called on the connection strand when the connection went down (reconnect hook)
	void set_disconnect_handler(std::function<void(securepath::error const&)>);

	/// called once the peer hello exchange succeeded (the link is really up)
	void set_connected_handler(std::function<void()>);

	/// send a commit push to the peer when the connection is ready (plan 4.2)
	void push(protocol::push_records const&);

	/// announce the heads of our replicated storages (the periodic anti-entropy tick,
	/// plan 4.4); a no-op until the hello exchange is done
	void announce_heads();

	/// tell the peer what our data role holds (record_data.txt RD13); a no-op until the
	/// hello exchange is done
	void announce(protocol::announce_data const&);

	/// tell a data server that records no longer name these data (RD9); only a data
	/// server link takes it, a no-op on a replication peer's connection
	void release(protocol::release_data const&);

	/// true for the link of a separate data server whose hello went through (RD12)
	bool is_data_server_link() const;
	/// the hello went through and the link is a data server's (true) or a replication peer's
	bool ready_as(bool data_server_link) const;

	/// tell a data server to hold copies of these data (RD13 replication); only a data
	/// server link takes it. True when it was sent
	bool replicate(protocol::replicate_data const&);

protected:
	void on_connected() override;
	void on_disconnected(securepath::error const& error) override;
	void on_received(octet_span) override;

public:
	// s2s packet handlers (public for the deserialiser dispatch)
	void operator()(protocol::peer_hello const&);
	void operator()(protocol::peer_heads const&);
	void operator()(protocol::pull_records const&);
	void operator()(protocol::response_envelopes const&);
	void operator()(protocol::push_records const&);
	void operator()(protocol::not_replicating const&);
	void operator()(protocol::request_key const&);
	void operator()(protocol::response_key const&);
	void operator()(protocol::announce_data const&);
	void operator()(protocol::release_data const&);
	void operator()(protocol::replicate_data const&);
	void operator()(protocol::request_replica_ticket const&);
	void operator()(protocol::response_replica_ticket const&);

private:
	void terminate(securepath::error const&);
	bool authenticate_transport();
	void send_hello();
	void send_our_heads();
	void send_packet(auto const& packet);
	bool check_ready(char const* what);
	bool check_peer(char const* what);
	void start_pulls(protocol::peer_heads const&);
	void request_pull(protocol::storage_id const&, crypto::public_key_id const&,
		sequence_number from, sequence_number to);
	void apply_envelopes(std::shared_ptr<storage> const&, std::deque<block_envelope> const&, char const* what);
	void request_signer_key(crypto::public_key_id const&);
	void resume_pulls();

private:
	// pushes and pull answers carry records like the client connection does: the
	// transport frame is the bound of a message
	serialisation::packet_deserialiser<protocol::s2s_types> deser_{network::max_frame_size};
	storage_server_context& sctx_;
	storage_data_context& dctx_;

	mutable std::mutex mutex_;
	/// set for an outgoing connection: the peer this connection must reach
	std::optional<peer_config> expected_;
	/// the verified remote server id, set after peer_hello
	std::optional<crypto::public_key_id> peer_id_;
	/// the remote is a separate data server (RD12), not a replication peer: it announces
	/// what it holds and takes no part in the record exchange
	bool data_server_link_{};
	std::map<protocol::storage_id, std::vector<origin_head>> peer_heads_;
	std::function<void(securepath::error const&)> on_disconnect_;
	std::function<void()> on_connected_;
	/// (storage, origin) pulls in flight, so periodic heads do not double-pull
	std::set<std::pair<protocol::storage_id, octet_vector>> pulling_;
	/// record signer keys asked from the peer (plan 5.2) by request id, so one unknown
	/// signer is asked once at a time and a negative answer frees it for a later try
	std::map<protocol::call_id, crypto::public_key_id> key_requests_;
	protocol::call_id next_cid_{1};
};

}
