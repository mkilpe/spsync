#include "request_handler.hpp"
#include "async_key_query.hpp"
#include "events.hpp"
#include "protocol/protocol.hpp"

#include <securepath/serialisation/util.hpp>

#include <infrastructure/packet_transport/client/packet_client.hpp>
#include <infrastructure/packet_transport/client/events.hpp>

#include <spsync/protocol/ports.hpp>

namespace securepath::sync::client {

struct request_handler::impl : public event_system::event_handler {
	impl(network::context& c, event_system::event_handler& h, database::connection_ptr db)
	: event_handler(h.event_loop())
	, handler(h)
	, context(c)
	, requests(db)
	, client(context, *this, db)
	, key_client(context, *this)
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
			auto data = decrypt(handle->packet().data, my_private_key(context.private_data()));
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
				, event_dest<packet_transport::events::on_error>(&impl::on_error)
				, event_dest<query_event>(&impl::on_query_event) );
	}

	void handle(packet_transport::in_packet_handle handle, protocol::request_packet const& p) {
		try {
			auto packet = handle->packet();

			if(requests.is_sender_banned(packet.signature.issuer())) {
				LOG_WARN("request from banned sender [kid=%]", packet.signature.issuer());
				return;
			}

			user sender{packet.signature.issuer(), p.sender_server};
			request_data rdata{sender, p.tag, p.data};

			auto rh = requests.add(rdata, packet);

			db_request req{{{rdata}, rh, request_state::waiting_for_verification}, packet};
			do_verify_data(std::move(req), false);
		} catch(std::exception const& ex) {
			LOG_WARN("exception while handling packet [ex=%]", ex.what());
		}
		handle->mark_seen();
	}

	void on_query_event(error err, std::optional<crypto::public_key> optkey, std::any userdata) {
		LOG_WARN("on_query_event [err=%, has key=%]", err, optkey ? "yes" : "no");
		if(db_request* data = std::any_cast<db_request>(&userdata)) {
			if(!err) {
				if(optkey) {
					context.public_keys().insert(*optkey);
					do_verify_data(*data, true);
				} else {
					data->state = request_state::no_key_found;
					requests.change_state(data->id, data->state);
					handler.emit<events::on_request>(*data);
				}
			} else {
				data->state = request_state::querying_key_failed;
				requests.change_state(data->id, data->state);
				handler.emit<events::on_request>(*data);
			}
		}
	}

	void do_verify_data(db_request req, bool notify_only_on_change) {
		request_state state = req.state;
		// see if we can directly check the signature
		auto pkey = context.public_keys().find(req.sender.id().public_key_id());
		if(pkey) {
			if(pkey->verify(req.payload.signature, serialisation::asn_der_serialise(req.payload.data))) {
				req.state = request_state::verification_succeeded;
			} else {
				LOG_WARN("packet not authentic [kid=%]", pkey->id());
				req.state = request_state::verification_failed;
			}
			requests.change_state(req.id, req.state);
		} else {
			key_client.query(req.sender, req);
		}
		if(!notify_only_on_change || req.state != state) {
			handler.emit<events::on_request>(req);
		}
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

public:
	mutable std::mutex mutex;
	network::context& context;
	event_system::event_handler& handler;
	account_info own_account;
	request_storage requests;
	packet_transport::packet_client client;
	async_key_query key_client;
};

request_handler::request_handler(network::context& context, event_system::event_handler& h, database::connection_ptr db)
: impl_(std::make_unique<impl>(context, h, db))
{
}

request_handler::~request_handler()
{
}

void request_handler::set_own_account(account_info u) {
	std::unique_lock l{impl_->mutex};
	impl_->own_account = std::move(u);
}

account_info request_handler::own_account() const {
	std::unique_lock l{impl_->mutex};
	return impl_->own_account;
}

void request_handler::connect(host_port const& server) {
	if(!impl_->own_account.me.is_valid()) {
		LOG_WARN("own id not set for request_handler");
		throw make_error(errc::constraint_violation, "own id not set");
	}
	impl_->client.connect(server.host);
}

void request_handler::close() {
	impl_->client.close();
}

request_storage& request_handler::requests() {
	return impl_->requests;
}

void request_handler::send_request(user receiver, std::string tag, octet_vector data) {
	LOG_TRACE("sending request [kid=%, tag=%]", receiver.id(), tag);

	std::unique_lock l{impl_->mutex};
	if(!impl_->own_account.me.is_valid()) {
		LOG_WARN("own id not set for request_handler");
		throw make_error(errc::constraint_violation, "own id not set");
	}

	auto opt_key = impl_->find_key(receiver.key_server(), receiver.id().public_key_id());
	if(!opt_key) {
		LOG_INFO("No public key found when sending request [key_id=%]", receiver.id().public_key_id().in_hex());
		throw make_error(crypto::errc::no_such_key, "Could not find requested public key for user");
	}
	impl_->context.public_keys().insert(*opt_key);

	protocol::request_packet p{std::move(tag), impl_->own_account.me.key_server(), std::move(data)};
	impl_->client.send_packet(
			serialisation::asn_der_serialise_choice<protocol::types>(p),
			packet_transport::receiver{receiver.id().public_key_id()});
}

void request_handler::try_evaluate_request(request_id id) {
	auto req = impl_->requests.find(id);
	if(!req) {
		throw make_error(securepath::errc::no_such_data, "invalid request id");
	}
	impl_->do_verify_data(std::move(*req), true);
}

void request_handler::remove_request(request_id id) {
	impl_->requests.remove(id);
}

void request_handler::emit_pending_requests() {
	LOG_TRACE("emit_pending_requests");
	impl_->client.emit_pending_packets();
	{
		auto list = impl_->requests.enumerate(request_state::waiting_for_verification);
		for(auto&& v : list) {
			impl_->do_verify_data(std::move(v), true);
		}
	}
	{
		// try again if querying key failed previously
		auto list = impl_->requests.enumerate(request_state::querying_key_failed);
		for(auto&& v : list) {
			impl_->do_verify_data(std::move(v), true);
		}
	}
}

}
