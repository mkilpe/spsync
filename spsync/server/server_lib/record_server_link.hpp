#pragma once

#include "peer_config.hpp"

#include <spsync/protocol/s2s_protocol.hpp>

#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/framing.hpp>
#include <securepath/serialisation/util.hpp>

#include <functional>
#include <mutex>
#include <vector>

namespace securepath::sync {

/**
 * The link of a separate data server to one of its record servers (record_data.txt
 * RD12/RD13): it dials the record server's s2s listener, which accepts configured data
 * servers for this and nothing else, says hello with its own key id and then announces
 * what it holds - everything when the link comes up (the availability tables are
 * transient), each data as it completes. The handshake verified the record server's key
 * against the root: handing it to the trust function is how a separate data server
 * learns the keys its tickets are signed with.
 */
class record_server_link : public network::encrypted_connection {
public:
	struct hooks {
		/// the announcements of everything held, for a link that just came up
		std::function<std::vector<protocol::announce_data>()> whole_view;
		/// the record server's authenticated key
		std::function<void(crypto::public_key const&)> trust;
		/// the link went down (reconnect)
		std::function<void()> disconnected;
		/// the hello exchange succeeded
		std::function<void()> connected;
	};

	record_server_link(network::context&, peer_config record_server, crypto::public_key_id own_id, hooks);
	~record_server_link();

	void start(std::chrono::seconds timeout);

	/// send when the link is up; dropped otherwise (the whole view follows the next connect)
	void announce(protocol::announce_data const&);

	bool ready() const;

protected:
	void on_connected() override;
	void on_disconnected(securepath::error const&) override;
	void on_received(octet_span) override;

public:
	// s2s packet handlers (public for the deserialiser dispatch)
	void operator()(protocol::peer_hello const&);

	/// whatever else a record server says on this link is not for a data server
	template<typename Packet>
	void operator()(Packet const&) {}

private:
	void send_packet(auto const& packet);

private:
	peer_config const record_server_;
	crypto::public_key_id const own_id_;
	hooks const hooks_;
	// nothing big is for a data server, but a record server that does not know the link's
	// role yet may send it: taken and dropped rather than refused
	serialisation::packet_deserialiser<protocol::s2s_types> deser_{network::max_frame_size};

	mutable std::mutex mutex_;
	bool ready_{};
};

}
