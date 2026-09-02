#pragma once

#include "storage_server_context.hpp"

#include <spsync/core/origin_head.hpp>
#include <spsync/protocol/s2s_protocol.hpp>

#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/serialisation/util.hpp>

#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

namespace securepath::sync {

/**
 * One server-to-server connection (plan 4.1), used for both directions: an outgoing
 * connection is dialed to a configured peer (connect_peer) and an incoming one is
 * accepted by the s2s listener. Both sides authenticate the remote ML-DSA key id
 * against the peer configuration (3.3), exchange peer_hello and then announce the
 * heads of their replicated storages. pull_records is served from the chain log;
 * push_records is applied with plan 4.2.
 */
class peer_connection : public network::encrypted_connection {
public:
	peer_connection(network::context&, storage_server_context&, network::handshake_data,
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

private:
	void terminate(securepath::error const&);
	bool authenticate_transport();
	void send_hello();
	void send_our_heads();
	void send_packet(auto const& packet);
	bool check_ready(char const* what);

private:
	serialisation::packet_deserialiser<protocol::s2s_types> deser_;
	storage_server_context& sctx_;

	mutable std::mutex mutex_;
	/// set for an outgoing connection: the peer this connection must reach
	std::optional<peer_config> expected_;
	/// the verified remote server id, set after peer_hello
	std::optional<crypto::public_key_id> peer_id_;
	std::map<protocol::storage_id, std::vector<origin_head>> peer_heads_;
	std::function<void(securepath::error const&)> on_disconnect_;
};

}
