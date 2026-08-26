#pragma once

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/client/contact_handler.hpp>
#include <spsync/client/events.hpp>
#include <spsync/client/protocol/contact.hpp>

#include <spsync/test/util.hpp>
#include <spsync/test/test_context.hpp>
#include <spsync/test/test_progress.hpp>
#include <spsync/test/test_server_runner.hpp>

namespace securepath::sync::client::test {

namespace {

host_port const local_key_server{"127.0.0.1", sync::default_key_server_port};
host_port const local_packet_server{"127.0.0.1", packet_transport::default_packet_server_port};

struct keep_db_type {} keep_db;

// This class is to test request and contact handlers
class test_client : public event_system::event_handler {
public:
	test_client(event_system::event_loop& loop, network::context& context, std::string const& dbname, host_port keys = local_key_server)
	: event_handler(loop)
	, conn(context, *this, sync::test::create_test_database(dbname))
	{
		account_info me{user{my_private_key(context.private_data()).id(), keys}, "test"};
		conn.set_own_account(me);
	}

	test_client(keep_db_type, event_system::event_loop& loop, network::context& context, std::string const& dbname, host_port keys = local_key_server)
	: event_handler(loop)
	, conn(context, *this, sync::test::create_test_database(dbname, false))
	{
		account_info me{user{my_private_key(context.private_data()).id(), keys}, "test"};
		conn.set_own_account(me);
	}

	~test_client() {
		event_handler::stop_handler();
	}

	void connect() {
		conn.connect(local_packet_server);
	}

	void disconnect() {
		conn.close();
	}

	void on_connect() {
		LOG_TRACE("on_connect");
		try {
			connected.set_value();
		} catch(...) {}
	}

	void on_disconnect(error err) {
		LOG_TRACE("on_disconnect [err={}]", err);
		try {
			connected.set_exception(std::make_exception_ptr(err));
		} catch(...) {}
	}

	void on_request(request req) {
		std::unique_lock l{mutex};
		requests.push_back(req);
	}

	void on_contacting(request req, std::string name, std::string message) {
		LOG_TRACE("contacting [name={}, message={}]", name, message);
		std::unique_lock l{mutex};
		requests.push_back(req);
	}

	void on_invitation(request req, storage_info, std::string name, std::string message) {
		LOG_TRACE("invitation [name={}, message={}]", name, message);
		std::unique_lock l{mutex};
		requests.push_back(req);
	}

	void handle_event(std::unique_ptr<event_base> ev) override {
		dispatch( *ev
				, event_dest<events::on_connect>(&test_client::on_connect)
				, event_dest<events::on_disconnect>(&test_client::on_disconnect)
				, event_dest<events::on_request>(&test_client::on_request)
				, event_dest<events::on_contacting>(&test_client::on_contacting)
				, event_dest<events::on_invitation>(&test_client::on_invitation) );
	}

	void wait_for_connect() {
		auto f = connected.get_future();
		REQUIRE(f.wait_for(2s) == std::future_status::ready);
   		connected = std::promise<void>{};
	}

	bool has_request(request_state state, user sender, std::string tag, octet_vector data) const {
		std::unique_lock l{mutex};
		auto it = std::find_if(requests.begin(), requests.end(), [&](auto v)
			{
				return v.state == state && v.sender == sender && v.tag == tag && v.data == data;
			});
		return it != requests.end();
	}

	bool has_contacting(request_state state, user sender, std::string name, std::string message) const {
		protocol::contact_data data{name, message};
		return has_request(state, sender, contact_tag, serialisation::asn_der_serialise(data));
	}

	bool has_storage_invitation(request_state state, user sender, std::string name, std::string message, storage_info info) const {
		protocol::invitation_data data{
				info.sid,
				info.key_server,
				info.sync_server,
				info.chain_id,
				info.enc_keys,
				name,
				message
			};
		return has_request(state, sender, invite_tag, serialisation::asn_der_serialise(data));
	}

	bool storage_has(request_state state, user sender, std::string tag, octet_vector data) {
		auto list = conn.requests().enumerate();
		auto it = std::find_if(list.begin(), list.end(), [&](auto v)
			{
				return v.state == state && v.sender == sender && v.tag == tag && v.data == data;
			});
		return it != list.end();
	}

	void clear_requests() {
		std::unique_lock l{mutex};
		requests.clear();
	}

	std::size_t requests_size() const {
		std::unique_lock l{mutex};
		return requests.size();
	}

public:
	mutable std::mutex mutex;
	contact_handler conn;
	std::promise<void> connected;
	std::deque<request> requests;
};
}

}