
#include "json_manager.hpp"
#include "json_helpers.hpp"

#include <groupchat/core/groupchat.hpp>
#include <groupchat/core/events.hpp>
#include <groupchat/core/version.hpp>
#include <spsync/client/events.hpp>
#include <spsync/client/request.hpp>
#include <spsync/client/protocol/contact.hpp>
#include <spsync/core/types.hpp>
#include <spsync/core/version.hpp>
#include <spsync/util/object_id.hpp>
#include <spsync/protocol/ports.hpp>

#include <infrastructure/key_client_lib/unknown_user_key_client.hpp>
#include <infrastructure/key_server/server_lib/defaults.hpp>
#include <infrastructure/packet_transport/protocol/ports.hpp>

#include <securepath/event_system/event_loop.hpp>
#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>
#include <securepath/version.hpp>

#include <mutex>

namespace securepath::groupchat::json_protocol {

void initialise_logging() {
	log::backend::add_backend<log::backend::file_output>("file", "gc.log");
	LOG_TRACE("logging initialised");
}

struct chat_entry {
	std::string name;
	chat_id id;
	std::deque<message> messages;
};

bool chats_sort(chat_entry const& e1, chat_entry const& e2) {
	if(e1.messages.empty()) { return false; }
	if(e2.messages.empty()) { return true;  }
	return e1.messages[0].sender_time >= e2.messages[0].sender_time;
}

struct json_manager::impl
	: public event_system::event_handler
	, public groupchat
{
public:
	impl(event_system::event_loop& l, event_callback func)
	: event_handler(l)
	, groupchat(*this, groupchat_config{})
	, notify(std::move(func))
	{}

	impl(event_system::event_loop& l, network::context& context, event_callback func, std::string path)
	: event_handler(l)
	, groupchat(*this, context, groupchat_config{std::move(path)})
	, notify(std::move(func))
	{}

	~impl() {
		stop_handler();
	}

	/*void on_connect(server_id sid) {
		json::object event{
			{"connection", "online"},
			{"server", sid}};
		notify(event_type::state_change, json::serialize(json::object{{"type", "connection"}, {"data", event}}));
	}*/

	/*void on_disconnect(server_id sid, error err) {
		json::object event{
			{"connection", "offline"},
			{"server", sid}};
		if(err) {
			event["error"] = error_to_object(err);
		}
		notify(event_type::state_change, json::serialize(json::object{{"type", "connection"}, {"data", event}}));
	}*/

	void on_create(server_id sid, chat_id cid, error err) {
		json::object event{
			{"action", "create"},
			{"server", sid},
			{"chat", to_hex(cid)}};
		if(err) {
			event["error"] = error_to_object(err);
		}
		notify(event_type::state_change, json::serialize(json::object{{"type", "chat"}, {"data", event}}));
	}

	void on_change_user(server_id sid, chat_id cid, sync::users change, error err) {
	}

	void on_join(server_id sid, chat_id cid, error err) {
		json::object event{
			{"action", "join"},
			{"server", sid},
			{"chat", to_hex(cid)}};
		if(err) {
			event["error"] = error_to_object(err);
		}
		notify(event_type::state_change, json::serialize(json::object{{"type", "chat"}, {"data", event}}));
	}

	void on_message(server_id sid, chat_id cid, msg_data md, msg_change change) {
		LOG_TRACE("json_manager::on_message [sid=%, cid=%]", sid, to_hex(cid));
		json::object message{
			{"message", md.message},
			{"date", time_to_string(md.sender_time)},
			{"index", change.new_index},
			{"oldindex", change.old_index},
			{"state", change.state == msg_state::in_sync ? "in_sync" : "pending"},
			{"id", change.id.to_hex()},
			{"sender", sender_to_object(md.sender)}};

		json::object event{
			{"action", "message"},
			{"server", sid},
			{"chat", to_hex(cid)},
			{"message", message}};
		notify(event_type::state_change, json::serialize(json::object{{"type", "chat"}, {"data", event}}));
	}

	void on_connect() {
		json::object event{
			{"connection", "online"}};
		notify(event_type::state_change, json::serialize(json::object{{"type", "connection"}, {"data", event}}));
	}

	void on_disconnect(error err) {
		json::object event{
			{"connection", "offline"}};
		if(err) {
			event["error"] = error_to_object(err);
		}
		notify(event_type::state_change, json::serialize(json::object{{"type", "connection"}, {"data", event}}));
	}

	void on_contacting(sync::client::request const& req
		, std::string const& name
		, std::string const& message)
	{
		LOG_TRACE("json_manager::on_contacting [kid=%, name=%, msg=%]", req.sender, name, message);
		notify(event_type::request, json::serialize(json::object{{"type", "contact"}
			, {"data", contacting_to_object(req, name, message)}}));
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
			//, event_dest<events::on_connect>(&impl::on_connect)
			//, event_dest<events::on_disconnect>(&impl::on_disconnect)
			, event_dest<events::on_create>(&impl::on_create)
			, event_dest<events::on_change_user>(&impl::on_change_user)
			, event_dest<events::on_join>(&impl::on_join)
			, event_dest<events::on_message>(&impl::on_message)
			, event_dest<sync::client::events::on_connect>(&impl::on_connect)
			, event_dest<sync::client::events::on_disconnect>(&impl::on_disconnect)
			, event_dest<sync::client::events::on_contacting>(&impl::on_contacting) );
	}

	host_port extract_host_port(json::object const& obj, std::string const& default_host, uint16_t default_port) {
		auto opt_server = extract_opt<json::object>(obj, "server");
		auto opt_host = opt_server ? extract_opt<std::string>(*opt_server, "host") : std::nullopt;
		auto opt_port = opt_server ? extract_opt<int>(*opt_server, "port") : std::nullopt;
		return host_port{opt_host.value_or(default_host), static_cast<std::uint16_t>(opt_port.value_or(default_port))};
	}

	gc_servers extract_gc_servers(json::object const& obj) {
		auto opt_server = extract_opt<json::object>(obj, "server");
		auto opt_host = opt_server ? extract_opt<std::string>(*opt_server, "host") : std::nullopt;
		auto opt_keyport = opt_server ? extract_opt<int>(*opt_server, "keyport") : std::nullopt;
		auto opt_syncport = opt_server ? extract_opt<int>(*opt_server, "syncport") : std::nullopt;
		auto opt_packetport = opt_server ? extract_opt<int>(*opt_server, "packetport") : std::nullopt;
		return gc_servers{
			opt_host.value_or("gc.securepath.fi"),
			static_cast<std::uint16_t>(opt_keyport.value_or(sync::default_key_server_port)),
			static_cast<std::uint16_t>(opt_syncport.value_or(sync::default_storage_server_port)),
			static_cast<std::uint16_t>(opt_packetport.value_or(packet_transport::default_packet_server_port))
		};
	}

	host_port extract_storage_host_port(json::object const& obj) {
		auto info = account_info();
		if(info) {
			return extract_host_port(obj, info->server.host, info->server.port);
		} else {
			return extract_host_port(obj, "gc.securepath.fi", sync::default_storage_server_port);
		}
	}
	host_port extract_key_host_port(json::object const& obj) {
		auto info = account_info();
		if(info) {
			return extract_host_port(obj, info->me.key_server().host, info->me.key_server().port);
		} else {
			return extract_host_port(obj, "gc.securepath.fi", sync::default_key_server_port);
		}
	}

	json::object sender_to_object(user_id const& uid) {
		auto opt_contact = contacts().find(uid);
		auto info = account_info();
		bool is_me = info && info->me.id().public_key_id() == uid.public_key_id();

		return json::object{
				{"name", opt_contact ? opt_contact->name() : uid.public_key_id().in_hex()},
				{"id", uid.public_key_id().in_hex()},
				{"contact", static_cast<bool>(opt_contact)},
				{"me", static_cast<bool>(is_me)}};
	}

	json::object message_to_object(message const& m) {
		//t: indicate if the message was sent by us
		return json::object{
			{"message", m.data},
			{"date", time_to_string(m.sender_time)},
			{"index", m.index},
			{"id", m.mid.to_hex()},
			{"sender", sender_to_object(m.sender_id)}};
	}

	std::vector<chat_entry> get_chats(std::optional<message_search> s) const {
		std::vector<chat_entry> ret;
		for(auto const& c : connections()) {
			for(auto const& c_id : c->channel_ids()) {
				channel& ch = c->get(c_id);
				ret.push_back(chat_entry{ch.name(), ch.id()});
				if(s) {
					ret.back().messages = ch.messages(*s);
				}
			}
		}
		return ret;
	}

public:
	std::function<void(event_type, std::string)> const notify;
};

json_manager::json_manager(event_callback func)
: loop_(std::make_unique<event_system::single_thread_event_loop>())
, impl_(std::make_unique<impl>(*loop_, std::move(func)))
{
	LOG_TRACE("json_manager ctor %", this);
}

json_manager::json_manager(network::context& context, event_callback func, std::string path)
: loop_(std::make_unique<event_system::single_thread_event_loop>())
, impl_(std::make_unique<impl>(*loop_, context, std::move(func), std::move(path)))
{
	LOG_TRACE("json_manager ctor %", this);
}

json_manager::~json_manager()
{
	LOG_TRACE("json_manager dtor %", this);
}

std::string json_manager::get_account() const {
	return call([&]{
		auto acc = impl_->account_info();
		if(acc) {
			json::object user{{"name", acc->name}};
			json::object ret{
				{"user", user},
				{"id", acc->me.id().public_key_id().in_hex()},
				{"server", server_to_object(acc->server)}};
			return json::serialize(ret);
		} else {
			return std::string("{}");
		}
	});
}

std::string json_manager::create_account(std::string_view const& arg) {
	LOG_TRACE("json_manager::create_account");
	return call([&]{
		auto acc = impl_->account_info();
		if(acc) {
			LOG_WARN("account already exists");
			return error_to_json(make_error(errc::invalid_state, "account already exists"));
		} else {
			json::object obj = json::parse(arg).as_object();
			impl_->create_account(impl_->extract_gc_servers(obj), extract<std::string>(obj, "name"));
			return get_account();
		}
	});
}

std::string json_manager::get_config(std::string_view const&) const {
	return call([&]{
		return "{}";
	});
}

std::string json_manager::set_config(std::string_view const&) {
	return call([&]{
		return "{}";
	});
}

std::string json_manager::connect() {
	return call([&]{
		impl_->connect();
		return std::string("{}");
	});
}

std::string json_manager::disconnect() {
	return call([&]{
		impl_->disconnect();
		return std::string("{}");
	});
}

std::string json_manager::get_contacts(std::string_view const&) const {
	return call([&]{
		auto contacts = impl_->contacts().enumerate();
		json::array json_c;
		for(auto& v : contacts) {
			std::string key_id = v->id().public_key_id().in_hex();
			json_c.push_back(json::object{
				{"name", v->name()},
				{"id", key_id},
				{"complete", v->state() == sync::client::contact_state::complete} });
		}
		json::object ret{{"data", json_c}};
		return json::serialize(ret);
	});
}

std::string json_manager::add_contact(std::string_view const& arg) {
	return call([&]{
		json::object obj = json::parse(arg).as_object();
		auto name = extract<std::string>(obj, "name");
		auto message = extract_opt<std::string>(obj, "message");
		auto key_id_string = extract<std::string>(obj, "id");

		crypto::public_key_id key_id{key_id_string};
		auto contact = impl_->contacts().find(key_id);

		if(contact && contact->state() == sync::client::contact_state::complete) {
			contact->set_name(name);
		} else {
			user receiver{key_id, impl_->extract_key_host_port(obj)};
			impl_->request_handler().add_contact(receiver, name, message.value_or(""));
		}

		return json::serialize(json::object{{"name", name}, {"id", key_id.in_hex()}});
	});
}

std::string json_manager::get_chats(std::string_view const& arg) const {
	return call([&]{
		std::optional<message_search> s;

		if(!arg.empty()) {
			json::object args = json::parse(arg).as_object();
			auto msg_arg = extract_opt<json::object>(args, "message");
			int msg_count = msg_arg ? extract_opt<int>(*msg_arg, "count").value_or(1) : 1;
			bool message_order = msg_arg ? extract_opt<std::string>(*msg_arg, "order").value_or("descending") == "ascending" : false;

			if(msg_arg) {
				s = message_search{
						0,
						static_cast<std::size_t>(msg_count),
						message_order ? msg_order::index_ascending : msg_order::index_descending};
			}
		}

		// first load channels so that we have all the info we need to enumerate them
		impl_->load_channels();

		auto list = impl_->get_chats(s);
		if(s) {
			std::stable_sort(list.begin(), list.end(), chats_sort);
		}

		json::array ret;
		for(auto&& v : list) {
			json::array arr;
			for(auto&& m : v.messages) {
				arr.push_back(impl_->message_to_object(m));
			}
			ret.push_back(json::object{{"name", v.name}, {"id", to_hex(v.id)}, {"messages", arr}});

		}
		return json::serialize(json::object{{"data", ret}});
	});
}

std::string json_manager::create_chat(std::string_view const& arg) {
	return call([&]{
		json::object obj = json::parse(arg).as_object();
		std::string name = extract<std::string>(obj, "name");
		auto conn = impl_->load(impl_->extract_storage_host_port(obj));
		conn->connect().get(); //t: make this whole thing correctly async

		users member_list;
		std::optional<json::array> members = extract_opt<json::array>(obj, "members");
		if(members) {
			for(auto m : *members) {
				json::object m_obj = m.as_object();
				std::string kid = extract<std::string>(m_obj, "user");
				member_list.add(sync::util::user_access{crypto::public_key_id{kid}
					, sync::util::access_type::user_management_access});
			}
		}

		auto cid = conn->create_chat(name, member_list).id();
		return json::serialize(json::object{{"name", name}, {"id", to_hex(cid)}});
	});
}

std::string json_manager::join_chat(std::string_view const& arg) {
	return call([&]{
		json::object obj = json::parse(arg).as_object();
		chat_id cid = from_hex(extract<std::string>(obj, "id"));
		auto conn = impl_->load(impl_->extract_storage_host_port(obj));
		conn->connect().get(); //t: make this whole thing correctly async
		conn->join(cid);
		return json::serialize(json::object{{"id", to_hex(cid)}});
	});
}

std::string json_manager::get_chat_members(std::string_view const& arg) const {
	return call([&]{
		json::object obj = json::parse(arg).as_object();
		chat_id cid = from_hex(extract<std::string>(obj, "id"));

		auto hp = impl_->channel_ids().find_server(cid);
		if(!hp) {
			LOG_TRACE("no chat with id %", to_hex(cid));
			return error_to_json(make_error(errc::no_such_data, "could not find chat"));
		}

		auto conn = impl_->load(*hp);
		auto& channel = conn->get(cid);

		json::array m_arr;
		auto members = channel.members();
		for(auto const& m : members) {
			auto user_id = m->id();
			auto opt_contact = impl_->contacts().find(user_id);

			m_arr.push_back(json::object{
				{"name", opt_contact ? opt_contact->name() : user_id.public_key_id().in_hex()},
				{"status", to_string(m->status())},
				{"id", user_id.public_key_id().in_hex()},
				{"contact", static_cast<bool>(opt_contact)}});
		}
		return json::serialize(json::object{{"data", m_arr}});
	});
}

static users parse_users(json::object const& obj) {
	auto opt_add_m = extract_opt<json::array>(obj, "add");
	auto opt_remove_m = extract_opt<json::array>(obj, "remove");

	users change{sync::users_change_mode::delta};
	if(opt_add_m) {
		for(auto m : *opt_add_m) {
			json::object m_obj = m.as_object();
			std::string kid = extract<std::string>(m_obj, "user");
			change.add(sync::util::user_access{crypto::public_key_id{kid}
				, sync::util::access_type::user_management_access});
		}
	}
	if(opt_remove_m) {
		for(auto m : *opt_remove_m) {
			json::object m_obj = m.as_object();
			std::string kid = extract<std::string>(m_obj, "user");
			change.remove(crypto::public_key_id{kid});
		}
	}

	return change;
}

std::string json_manager::change_chat_member(std::string_view const& arg) {
	return call([&]{
		json::object obj = json::parse(arg).as_object();
		chat_id cid = from_hex(extract<std::string>(obj, "id"));

		auto hp = impl_->channel_ids().find_server(cid);
		if(!hp) {
			return error_to_json(make_error(errc::no_such_data, "could not find chat"));
		}

		users change = parse_users(obj);

		if(change.empty()) {
			return error_to_json(make_error(errc::invalid_data, "no members to change"));
		}

		auto conn = impl_->load(*hp);
		auto& channel = conn->get(cid);

		channel.apply(change);

		return json::serialize(json::object{});
	});
}

std::string json_manager::get_messages(std::string_view const& arg) const {
	LOG_TRACE("get_messages: %", arg);
	return call([&]{
		json::object obj = json::parse(arg).as_object();
		chat_id cid = from_hex(extract<std::string>(obj, "id"));

		message_search ms_option;

		ms_option.start_index = extract_opt<int>(obj, "start").value_or(0);
		ms_option.max_count = extract_opt<int>(obj, "count").value_or(0);
		ms_option.order = (extract_opt<std::string>(obj, "order").value_or("descending") == "descending")
			? msg_order::index_descending : msg_order::index_ascending;

		auto hp = impl_->channel_ids().find_server(cid);
		if(!hp) {
			return error_to_json(make_error(errc::no_such_data, "could not find chat"));
		}

		auto conn = impl_->load(*hp);
		auto& channel = conn->get(cid);

		json::array m_arr;
		for(auto m : channel.messages(ms_option)) {
			m_arr.push_back(impl_->message_to_object(m));
		}
		return json::serialize(json::object{{"data", m_arr}});
	});
}

std::string json_manager::send_message(std::string_view const& arg) {
	return call([&]{
		json::object obj = json::parse(arg).as_object();
		chat_id cid = from_hex(extract<std::string>(obj, "id"));
		std::string message = extract<std::string>(obj, "message");

		auto hp = impl_->channel_ids().find_server(cid);
		if(!hp) {
			return error_to_json(make_error(errc::no_such_data, "could not find chat"));
		}

		auto conn = impl_->load(*hp);
		auto& channel = conn->get(cid);

		auto msg = channel.send_message(message);
		return json::serialize(impl_->message_to_object(msg));
	});
}

//supported qr codes:
//1) sp-gc:{"type":"user","data":{"id":"BF42982C6801562694A3B315009E8777FF751DD321DAA2753AD41895865A55D9","name":"my test name","server":{"host":"gc.securepath.fi"}}}
//2) sp-gc:{"type":"join","data":{"id":"30202290BB417247B4D91F7E72544403","server":{"host":"gc.securepath.fi"}}}
std::string json_manager::handle_qr_code(std::string_view const& arg) {
	return call([&]{
		if(!arg.starts_with("sp-gc:")) {
			LOG_WARN("qr code data does not start with 'sp-gc:' [data=%]", arg);
			return error_to_json(make_error(errc::invalid_data, "invalid qr code data"));
		}
		json::object obj = json::parse(arg.substr(6)).as_object();
		auto type = extract<std::string>(obj, "type");

		json::object type_res;
		if(type == "user") {
			auto s = json::serialize(extract<json::object>(obj, "data"));
			type_res = json::parse(add_contact(s)).as_object();
		} else if(type == "join") {
			auto s = json::serialize(extract<json::object>(obj, "data"));
			type_res = json::parse(join_chat(s)).as_object();
		} else {
			LOG_WARN("qr code data has unknown type [data=%]", arg);
			return error_to_json(make_error(errc::invalid_data, "unknown type in qr code"));
		}

		return json::serialize(json::object{{"type", type}, {"data", type_res}});
	});
}

std::string json_manager::get_version() const {
	return call([&]{
		json::object ver_obj{
			{"groupchat", securepath::groupchat::version().to_string()},
			{"spsync", sync::version().to_string()},
			{"splib", securepath::library_version().to_string()}};

		json::object info{
			{"version", ver_obj},
			{"built", __DATE__},
			{"license", "<todo>"}};

		return json::serialize(info);
	});
}

std::string json_manager::get_requests(std::string_view const&) const {
	return call([&]{
		json::array arr;
		auto list = impl_->requests().enumerate();
		for(auto&& v : list) {
			if(v.tag == sync::client::contact_tag) {
				auto data = serialisation::asn_der_deserialise<sync::client::protocol::contact_data>(v.data);
				arr.push_back(contacting_to_object(v, data.name, data.message));
			}
		}
		return json::serialize(json::object{{"data", arr}});
	});
}

std::string json_manager::request_action(std::string_view const& arg) {
	return call([&]{
		json::object obj = json::parse(arg).as_object();
		std::string action = extract<std::string>(obj, "action");
		auto id = extract<sync::client::request_id>(obj, "requestid");

		json::object result;

		auto& rh = impl_->request_handler();
		if(action == "add_contact") {
			auto contact = rh.accept_contact_request(id);
			result = json::object{{"name", contact->name()}, {"id", contact->id().public_key_id().in_hex()}};
		} else if(action == "remove") {
			rh.remove_request(id);
		} else if(action == "ban") {
			auto req = impl_->requests().find(id);
			if(!req) {
				throw make_error(securepath::errc::no_such_data, "no such contact request");
			}
			impl_->requests().ban_sender(req->sender.id().public_key_id());
			rh.remove_request(id);
		} else if(action == "retry") {
			rh.try_evaluate_request(id);
		}
		return json::serialize(result);
	});
}

void json_manager::close() {

}

}