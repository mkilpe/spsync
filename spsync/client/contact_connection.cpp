#include "contact_connection.hpp"
#include "events.hpp"
#include "protocol/protocol.hpp"

#include <securepath/serialisation/util.hpp>

#include <infrastructure/key_client_lib/unknown_user_key_client.hpp>
#include <infrastructure/packet_transport/client/packet_client.hpp>
#include <infrastructure/packet_transport/client/events.hpp>

#include <spsync/protocol/ports.hpp>

namespace securepath::sync::client {

//t: move else where
namespace {
	struct packet_info {
		int retry_count{0};

		template<typename Ar>
		void serialise(Ar& ar) {
			serialisation::sequence<Ar> seq(ar);
			seq & retry_count;
		}
	};
}

struct contact_connection::impl : public event_system::event_handler {
	impl(network::context& c, event_system::event_handler& h, database::connection_ptr db)
	: event_handler(h.event_loop())
	, handler(h)
	, context(c)
	, contacts(db)
	, client(context, *this, db)
	{
	}

	~impl() {
		stop_handler();
	}

	void on_connect() {
		LOG_TRACE("contact connection connected");
		handler.emit<events::on_connect>();
	}

	void on_disconnect(error const& err) {
		LOG_TRACE("contact connection disconnected [err=%]", err);
		handler.emit<events::on_disconnect>(err);
	}

	void on_packet(packet_transport::in_packet_handle handle) {
		LOG_TRACE("on_packet");
		try {
			auto p = handle->packet();
			auto data = decrypt(p.data, my_private_key(context.private_data()));
			serialisation::asn_der_deserialise_choice<protocol::types>(data,
				[&](auto const& packet)
				{
					this->handle(handle, packet);
				});
		} catch(std::exception const& ex) {
			LOG_WARN("exception while handling packet [ex=%]", ex.what());
			handle->mark_seen();
		}
	}

	void on_error(packet_transport::packet_dir d, packet_transport::packet_key_type key, error const& err) {
		LOG_TRACE("client packet error [key=%, err=%]", key, err);
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) {
		dispatch( *ev
				, event_dest<packet_transport::events::on_connect>(&impl::on_connect)
				, event_dest<packet_transport::events::on_disconnect>(&impl::on_disconnect)
				, event_dest<packet_transport::events::on_packet>(&impl::on_packet)
				, event_dest<packet_transport::events::on_error>(&impl::on_error) );
	}

	void handle(packet_transport::in_packet_handle handle, protocol::contacting const& p) {
		try {
			auto packet = handle->packet();
			auto sig = packet.signature;
			auto pkey = find_key(p.sender_server, sig.issuer());
			if(pkey) {
				if(pkey->verify(sig, serialisation::asn_der_serialise(packet.data))) {
					LOG_TRACE("adding contact (request) [kid=%]", pkey->id());
					if(contacts.find(user_id{pkey->id()})) {
						LOG_WARN("already had the contact [kid=%]", pkey->id());
					} else {
						auto contact = contacts.add(user_id{pkey->id()});
						contact->set_server(p.sender_server);
						contact->set_state(contact_state::request);
						contact->set_contacting_data(p.data);
						handler.emit<events::on_contacting>(pkey->id(), p.tag, p.data);
					}
				} else {
					LOG_WARN("packet not authentic [kid=%]", pkey->id());
					throw make_error(crypto::errc::signature_not_authentic, "packet signature not authentic");
				}
			} else {
				LOG_WARN("no key for incoming packet [kid=%]", sig.issuer());
			}
			handle->mark_seen();
		} catch(std::exception const& ex) {
			LOG_WARN("exception while handling packet [ex=%]", ex.what());
			auto info = handle->data<packet_info>();
			if(info) {
				if(info->retry_count > 5) {
					handle->mark_seen();
				} else {
					++info->retry_count;
					LOG_TRACE("increasing retry count [count=%]", info->retry_count);
					handle->set_data(*info);
				}
			} else {
				handle->set_data(packet_info{});
			}
		}
	}

	void handle(packet_transport::in_packet_handle handle, protocol::chat_invite const& p) {

	}

	std::optional<crypto::public_key> find_key(host_port const& server, crypto::public_key_id const& key_id) {
		auto pkey = context.public_keys().find(key_id);
		if(!pkey) {
			pkey = query_key(server, key_id);
			if(pkey) {
				context.public_keys().insert(*pkey);
			} else {
				LOG_INFO("Could not query public key [kid=%, host=%, port=%]", key_id, server.host, server.port);
			}
		}
		return pkey;
	}

	std::optional<crypto::public_key> query_key(host_port const& server, crypto::public_key_id const& key_id) {
		LOG_TRACE("query key [kid=%, host=%, port=%]", key_id, server.host, server.port);
		auto key = context.public_keys().find(key_id);
		if(!key) {
			//t: non-blocking
			key_client::unknown_user_key_client client{context};
			client.connect(server.host, server.port);
			client.wait_for_connection();
			key = client.find_key(key_id);
		}
		return key;
	}

	void send_contacting(user const& receiver, std::string tag, octet_vector data) {
		protocol::contacting p{std::move(tag), own_id.key_server(), std::move(data)};
		client.send_packet(
			serialisation::asn_der_serialise_choice<protocol::types>(p),
			packet_transport::receiver{receiver.id().public_key_id()});
	}

public:
	mutable std::mutex mutex;
	network::context& context;
	event_system::event_handler& handler;
	user own_id;
	contact_list contacts;
	packet_transport::packet_client client;
};

contact_connection::contact_connection(network::context& context, event_system::event_handler& h, database::connection_ptr db)
: impl_(std::make_unique<impl>(context, h, db))
{
}

contact_connection::~contact_connection()
{
}

void contact_connection::set_own_id(user u) {
	std::unique_lock l{impl_->mutex};
	impl_->own_id = std::move(u);
}

void contact_connection::connect(host_port const& server) {
	if(!impl_->own_id.is_valid()) {
		LOG_WARN("own id not set for contact_connection");
		throw make_error(errc::constraint_violation, "own id not set");
	}
	impl_->client.connect(server.host);
}

void contact_connection::close() {
	impl_->client.close();
}

contact_list& contact_connection::contacts() {
	return impl_->contacts;
}

std::unique_ptr<contact> contact_connection::add_contact(user receiver, std::string tag, octet_vector data) {
	LOG_TRACE("add contact [kid=%]", receiver.id());
	std::unique_lock l{impl_->mutex};
	if(!impl_->own_id.is_valid()) {
		LOG_WARN("own id not set for contact_connection");
		throw make_error(errc::constraint_violation, "own id not set");
	}
	auto opt_key = impl_->find_key(receiver.key_server(), receiver.id().public_key_id());
	if(!opt_key) {
		LOG_INFO("No public key found when adding contact [key_id=%]", receiver.id().public_key_id().in_hex());
		throw make_error(crypto::errc::no_such_key, "Could not find requested public key for contact");
	}
	impl_->context.public_keys().insert(*opt_key);
	impl_->send_contacting(receiver, std::move(tag), std::move(data));
	auto contact = impl_->contacts.add(receiver.id());
	contact->set_server(receiver.key_server());
	return contact;
}

void contact_connection::emit_pending_events() {
	impl_->client.emit_pending_packets();
}

}
