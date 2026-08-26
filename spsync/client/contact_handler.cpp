#include "contact_handler.hpp"
#include <securepath/serialisation/vector.hpp>
#include "events.hpp"
#include "protocol/contact.hpp"

#include <securepath/serialisation/util.hpp>

namespace securepath::sync::client {

contact_handler::contact_handler(network::context& context, event_system::event_handler& h, database::connection_ptr db)
: event_handler(h.event_loop())
, request_handler(context, *this, db)
, callback_(h)
, contacts_(db)
{
}

contact_handler::~contact_handler()
{
	stop_handler();
}

std::unique_ptr<contact> contact_handler::add_contact(user receiver, std::string name, std::string message) {
	auto contact = contacts_.add(receiver.id());
	contact->set_state(contact_state::incomplete);
	contact->set_server(receiver.key_server());
	contact->set_name(name);

	auto info = own_account();
	protocol::contact_data data{info.name, std::move(message)};
	send_request(std::move(receiver), contact_tag, serialisation::asn_der_serialise(data));

	// send request above throws in case of error, so set the contact to be 'complete' as all worked
	contact->set_state(contact_state::complete);

	return contact;
}

std::unique_ptr<contact> contact_handler::accept_contact_request(request_id id) {
	auto r = requests().find(id);
	if(!r || r->tag != contact_tag) {
		throw make_error(securepath::errc::no_such_data, "no such contact request");
	}

	auto data = serialisation::asn_der_deserialise<protocol::contact_data>(r->data);

	auto contact = contacts_.add(r->sender.id());
	contact->set_state(contact_state::complete);
	contact->set_server(r->sender.key_server());
	contact->set_name(data.name);

	requests().remove(id);

	return contact;
}

contact_list& contact_handler::contacts() {
	return contacts_;
}

void contact_handler::send_storage_invitation(user receiver, std::string name, std::string message, storage_info info) {
	LOG_TRACE("sending storage invitation");
	protocol::invitation_data data
		{std::move(info.sid)
		,std::move(info.key_server)
		,std::move(info.sync_server)
		,std::move(info.chain_id)
		,std::move(info.enc_keys)
		,std::move(name)
		,std::move(message)};

	send_request(std::move(receiver), invite_tag, serialisation::asn_der_serialise(data));
}

void contact_handler::on_connect() {
	callback_.emit<events::on_connect>();
}

void contact_handler::on_disconnect(error err) {
	callback_.emit<events::on_disconnect>(err);
}

void contact_handler::on_request(request const& req) {
	LOG_TRACE("on_request [tag={}]", req.tag);
	try {
		if(req.tag == contact_tag) {
			auto contact = contacts_.find(req.sender.id());
			if(!contact) {
				auto data = serialisation::asn_der_deserialise<protocol::contact_data>(req.data);
				callback_.emit<events::on_contacting>(req, data.name, data.message);
			} else {
				LOG_INFO("contact request from user that is already a contact [user={}]", req.sender.id());
			}
		} else if(req.tag == invite_tag) {
			auto data = serialisation::asn_der_deserialise<protocol::invitation_data>(req.data);
			callback_.emit<events::on_invitation>(req, data.to_storage_info(), data.name, data.message);
		} else {
			callback_.emit<events::on_request>(req);
		}
	} catch(std::exception const& ex) {
		LOG_WARN("exception while handling contact request [ex={}]", ex.what());
	}
}

void contact_handler::handle_event(std::unique_ptr<event_system::event_base> ev) {
	dispatch( *ev
			, event_dest<events::on_connect>(&contact_handler::on_connect)
			, event_dest<events::on_disconnect>(&contact_handler::on_disconnect)
			, event_dest<events::on_request>(&contact_handler::on_request) );
}

}
