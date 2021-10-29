#pragma once

#include "cconn_protocol.hpp"
#include "types.hpp"
#include "contact_list.hpp"

#include <infrastructure/packet_transport/client/packet_client.hpp>
#include <infrastructure/packet_transport/client/events.hpp>

namespace securepath::groupchat {

class contact_connection : public event_system::event_handler {
public:
	contact_connection(network::context&, event_system::event_handler&, database::connection_ptr);
	~contact_connection();

	/// connect to the server
	void connect();

	/// close connection
	void close();

	/// Add contact and send contacting packet, server is the key server to query public key
	void add_contact(crypto::public_key_id const& id, std::string const& name, host_port const& server);

	//void invite_to_chat();

	void set_account_info(account_info);
	contact_list& contacts();

	void emit_pending_events();

private:
	void on_connect();
	void on_disconnect(error const&);
	void on_packet(packet_transport::in_packet_handle);
	void on_error(packet_transport::packet_dir, packet_transport::packet_key_type, error const&);
	void handle(packet_transport::in_packet_handle, protocol::contacting const&);
	void handle(packet_transport::in_packet_handle, protocol::chat_invite const&);
	void handle_event(std::unique_ptr<event_system::event_base> ev) override;

	std::optional<crypto::public_key> find_key(host_port const& server, crypto::public_key_id const& key_id);
	std::optional<crypto::public_key> query_key(host_port const&, crypto::public_key_id const&);
	void send_contacting(crypto::public_key_id const& id);

private:
	network::context& context_;
	event_system::event_handler& handler_;
	contact_list contacts_;
	packet_transport::packet_client client_;
	account_info info_;
};

}
