#pragma once

#include "peer_config.hpp"

#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/protocol/s2s_protocol.hpp>

#include <securepath/network/encryption/encrypted_connection.hpp>
#include <securepath/network/encryption/framing.hpp>
#include <securepath/serialisation/util.hpp>

#include <spsync/core/data/data_grant.hpp>
#include <spsync/transfer/pending_calls.hpp>

#include <asio/steady_timer.hpp>

#include <functional>
#include <map>
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
class record_server_link : public network::encrypted_connection, public std::enable_shared_from_this<record_server_link> {
public:
	struct hooks {
		/// the announcements of everything held, for a link that just came up
		std::function<std::vector<protocol::announce_data>()> whole_view;
		/// the record server's authenticated key
		std::function<void(crypto::public_key const&)> trust;
		/// the record server says no record names these data any more (RD9)
		std::function<void(protocol::storage_id const&, std::vector<data_id> const&)> release;
		/// the record server says this data server is to hold a copy of these data (RD13)
		std::function<void(protocol::storage_id const&, std::vector<data_descriptor> const&)> replicate;
		/// the link went down (reconnect)
		std::function<void()> disconnected;
		/// the hello exchange succeeded
		std::function<void()> connected;
	};

	/// silence_limit: how long the record server may take to answer a ticket request
	/// before the request fails and the link is given up (reconnected by the owner)
	record_server_link(network::context&, peer_config record_server, crypto::public_key_id own_id, hooks
		, std::chrono::seconds silence_limit = std::chrono::seconds{60});
	~record_server_link();

	void start(std::chrono::seconds timeout);
	void close() override;

	/// send when the link is up; dropped otherwise (the whole view follows the next connect)
	void announce(protocol::announce_data const&);

	using ticket_callback = std::move_only_function<void(util::result<data_grant>)>;

	/**
	 * Ask the record server for the ticket of a pull it told this data server to make
	 * (RD13 replication). Answered once: with what the record server says, or with an
	 * error when the link is or goes down before that.
	 */
	void request_ticket(protocol::storage_id const&, data_id const&, ticket_callback);

	bool ready() const;

protected:
	void on_connected() override;
	void on_disconnected(securepath::error const&) override;
	void on_received(octet_span) override;

public:
	// s2s packet handlers (public for the deserialiser dispatch)
	void operator()(protocol::peer_hello const&);
	void operator()(protocol::release_data const&);
	void operator()(protocol::replicate_data const&);
	void operator()(protocol::response_replica_ticket const&);

	/// whatever else a record server says on this link is not for a data server
	template<typename Packet>
	void operator()(Packet const&) {}

private:
	void send_packet(auto const& packet);
	/// answer the ticket requests still out: the link is gone
	void fail_requests(securepath::error const&);
	/// look every half limit whether a request is overdue, on the strand
	void watch();
	/// an overdue request fails and the link is given up; true while it goes on
	bool check_overdue();

private:
	peer_config const record_server_;
	crypto::public_key_id const own_id_;
	hooks const hooks_;
	// nothing big is for a data server, but a record server that does not know the link's
	// role yet may send it: taken and dropped rather than refused
	serialisation::packet_deserialiser<protocol::s2s_types> deser_{network::max_frame_size};

	std::chrono::seconds const silence_limit_;

	mutable std::mutex mutex_;
	bool ready_{};
	protocol::call_id next_call_{1};
	pending_calls<protocol::call_id, ticket_callback> requests_;
	asio::steady_timer silence_;
};

}
