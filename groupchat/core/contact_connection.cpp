#include "contact_connection.hpp"
#include "events.hpp"

#include <securepath/serialisation/util.hpp>

#include <infrastructure/key_client_lib/unknown_user_key_client.hpp>
#include <spsync/protocol/ports.hpp>

namespace securepath::groupchat {

contact_connection::contact_connection(network::context& context, event_system::event_handler& h, database::connection_ptr db)
: event_handler(h.event_loop())
, handler_(h)
, context_(context)
, contacts_(db)
, client_(context, *this, db)
{
}

contact_connection::~contact_connection()
{
	stop_handler();
}

void contact_connection::connect() {
	//t: parameterise own key server port
	if(info_.server.host.empty()) {
		throw make_error(errc::invalid_state, "own info not set");
	}
	client_.connect(info_.server.host);
}

void contact_connection::close() {
	client_.close();
}

contact_list& contact_connection::contacts() {
	return contacts_;
}

void contact_connection::on_connect() {
	LOG_TRACE("contact connection connected");
}

void contact_connection::on_disconnect(error const& err) {
	LOG_TRACE("contact connection disconnected [err=%]", err);
}

std::optional<crypto::public_key> contact_connection::find_key(host_port const& server, crypto::public_key_id const& key_id) {
	auto pkey = context_.public_keys().find(key_id);
	if(!pkey) {
		pkey = query_key(server, key_id);
		if(pkey) {
			context_.public_keys().insert(*pkey);
		} else {
			LOG_INFO("Could not query public key [kid=%, host=%, port=%]", key_id, server.host, server.port);
		}
	}
	return pkey;
}

void contact_connection::on_packet(packet_transport::in_packet_handle handle) {
	LOG_TRACE("on_packet");
	try {
		auto p = handle->packet();
		auto data = decrypt(p.data, my_private_key(context_.private_data()));
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

void contact_connection::on_error(packet_transport::packet_dir d, packet_transport::packet_key_type key, error const& err) {
	LOG_TRACE("client packet error [key=%, err=%]", key, err);
}

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

void contact_connection::handle(packet_transport::in_packet_handle handle, protocol::contacting const& p) {
	try {
		auto packet = handle->packet();
		auto sig = packet.signature;
		auto pkey = find_key(p.sender_key_server, sig.issuer());
		if(pkey) {
			if(pkey->verify(sig, serialisation::asn_der_serialise(packet.data))) {
				LOG_TRACE("adding contact (request) [kid=%, name=%]", pkey->id(), p.sender_name);
				auto contact = contacts_.add(user_id{pkey->id()});
				contact->set_name(p.sender_name);
				contact->set_server(p.sender_key_server);
				contact->set_state(contact_state::request);
				handler_.emit<events::on_contacting>(pkey->id(), p.sender_name);
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

void contact_connection::handle(packet_transport::in_packet_handle handle, protocol::chat_invite const& p) {

}

void contact_connection::handle_event(std::unique_ptr<event_system::event_base> ev) {
		dispatch( *ev
				, event_dest<packet_transport::events::on_connect>(&contact_connection::on_connect)
				, event_dest<packet_transport::events::on_disconnect>(&contact_connection::on_disconnect)
				, event_dest<packet_transport::events::on_packet>(&contact_connection::on_packet)
				, event_dest<packet_transport::events::on_error>(&contact_connection::on_error) );
}

std::optional<crypto::public_key> contact_connection::query_key(host_port const& server, crypto::public_key_id const& key_id) {
	LOG_TRACE("query key [kid=%, host=%, port=%]", key_id, server.host, server.port);
	auto key = context_.public_keys().find(key_id);
	if(!key) {
		//t: non-blocking
		key_client::unknown_user_key_client client{context_};
		client.connect(server.host, server.port);
		client.wait_for_connection();
		key = client.find_key(key_id);
	}
	return key;
}

void contact_connection::send_contacting(crypto::public_key_id const& id) {
	//t: parameterise own key server port
	host_port hp{info_.server};
	hp.port = sync::default_key_server_port;
	protocol::contacting p{info_.name, hp};
	client_.send_packet(serialisation::asn_der_serialise_choice<protocol::types>(p), packet_transport::receiver{id});
}

void contact_connection::add_contact(crypto::public_key_id const& id, std::string const& name, host_port const& server) {
	LOG_TRACE("add contact [kid=%, name=%]", id, name);
	auto opt_key = find_key(server, id);
	if(!opt_key) {
		LOG_INFO("No public key found when adding contact [name=%, key_id=%]", name, id.in_hex());
		throw make_error(crypto::errc::no_such_key, "Could not find requested public key for contact");
	}
	context_.public_keys().insert(*opt_key);
	send_contacting(id);
	auto contact = contacts_.add(user_id{id});
	contact->set_name(name);
	contact->set_server(server);
}

void contact_connection::set_account_info(account_info info) {
	info_ = std::move(info);
}

void contact_connection::emit_pending_events() {
	client_.emit_pending_packets();
}

}
