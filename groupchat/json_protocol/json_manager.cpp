
#include "json_manager.hpp"
#include "json_helpers.hpp"

#include <groupchat/core/groupchat.hpp>
#include <groupchat/core/events.hpp>
#include <groupchat/core/version.hpp>
#include <spsync/core/types.hpp>
#include <spsync/core/version.hpp>
#include <spsync/util/object_id.hpp>
#include <spsync/protocol/ports.hpp>

#include <infrastructure/key_client_lib/unknown_user_key_client.hpp>
#include <infrastructure/key_server/server_lib/defaults.hpp>

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

struct json_manager::impl
	: public event_system::event_handler
	, public groupchat
{
public:
	impl(event_system::event_loop& l, std::function<void(std::string)> func)
	: event_handler(l)
	, groupchat(*this, groupchat_config{})
	, notify(std::move(func))
	{}

	impl(event_system::event_loop& l, network::context& context, std::function<void(std::string)> func, std::string path)
	: event_handler(l)
	, groupchat(*this, context, groupchat_config{std::move(path)})
	, notify(std::move(func))
	{}

	~impl() {
		stop_handler();
	}

	void on_connect(server_id sid) {
		json::object event{
			{"connection", "online"},
			{"server", sid}};
		notify(json::serialize(json::object{{"type", "connection state changed"}, {"data", event}}));
	}

	void on_disconnect(server_id sid, error err) {
		json::object event{
			{"connection", "offline"},
			{"server", sid},
			{"error", error_to_object(err)}};
		notify(json::serialize(json::object{{"type", "connection state changed"}, {"data", event}}));
	}

	void on_create(server_id sid, chat_id cid, error err) {
		json::object event{
			{"action", "create"},
			{"server", sid},
			{"chat", to_hex(cid)},
			{"error", error_to_object(err)}};
		notify(json::serialize(json::object{{"type", "chat state changed"}, {"data", event}}));
	}

	void on_change_user(server_id sid, chat_id cid, sync::users change, error err) {
	}

	void on_join(server_id sid, chat_id cid, error err) {
		json::object event{
			{"action", "join"},
			{"server", sid},
			{"chat", to_hex(cid)},
			{"error", error_to_object(err)}};
		notify(json::serialize(json::object{{"type", "chat state changed"}, {"data", event}}));
	}

	void on_message(server_id sid, chat_id cid, message msg) {
		json::object event{
			{"action", "message"},
			{"server", sid},
			{"chat", to_hex(cid)},
			{"message", message_to_object(msg)}};
		notify(json::serialize(json::object{{"type", "chat state changed"}, {"data", event}}));
	}

	void handle_event(std::unique_ptr<event_system::event_base> ev) override {
		dispatch( *ev
			, event_dest<events::on_connect>(&impl::on_connect)
			, event_dest<events::on_disconnect>(&impl::on_disconnect)
			, event_dest<events::on_create>(&impl::on_create)
			, event_dest<events::on_change_user>(&impl::on_change_user)
			, event_dest<events::on_join>(&impl::on_join)
			, event_dest<events::on_message>(&impl::on_message) );
	}

	std::optional<crypto::public_key> query_key(host_port const& server, crypto::public_key_id const& key_id) {
		auto key = context().public_keys().find(key_id);
		if(!key) {
			//t: non-blocking
			key_client::unknown_user_key_client client{context()};
			client.connect(server.host, server.port);
			client.wait_for_connection();
			key = client.find_key(key_id);
		}
		return key;
	}


	host_port extract_host_port(json::object const& obj, std::string const& default_host, uint16_t default_port) {
		auto opt_server = extract_opt<json::object>(obj, "server");
		auto opt_host = opt_server ? extract_opt<std::string>(*opt_server, "host") : std::nullopt;
		auto opt_port = opt_server ? extract_opt<int>(*opt_server, "port") : std::nullopt;
		return host_port{opt_host.value_or(default_host), static_cast<std::uint16_t>(opt_port.value_or(default_port))};
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
			//t: also parameterise the key server port for own account
			return extract_host_port(obj, info->server.host, sync::default_key_server_port);
		} else {
			return extract_host_port(obj, "gc.securepath.fi", sync::default_key_server_port);
		}
	}

	void load_channels() {
		bool load = false;
		{
			std::unique_lock l{mutex};
			load = !channel_init;
			channel_init = true;
		}
		if(load) {
			groupchat::load_channels();
		}
	}

	json::object message_to_object(message const& m) {
		auto user_id = m.sender_id;
		auto opt_contact = contacts().find(user_id);

		return json::object{
			{"message", m.data},
			{"date", time_to_string(m.time)},
			{"seq", m.seq.value},
			{"id", m.mid.to_hex()},
			{"sender", json::object{
				{"name", opt_contact ? opt_contact->name() : user_id.public_key_id().in_hex()},
				{"id", user_id.public_key_id().in_hex()},
				{"contact", static_cast<bool>(opt_contact)}}}
			};
	}

public:
	std::mutex mutex;
	std::function<void(std::string)> const notify;
	bool channel_init{false};
};

json_manager::json_manager(std::function<void(std::string)> func)
: loop_(std::make_unique<event_system::single_thread_event_loop>())
, impl_(std::make_unique<impl>(*loop_, std::move(func)))
{
	LOG_TRACE("json_manager ctor %", this);
}

json_manager::json_manager(network::context& context, std::function<void(std::string)> func, std::string path)
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
				{"id", acc->key_id.in_hex()},
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
			impl_->create_account(impl_->extract_storage_host_port(obj), extract<std::string>(obj, "name"));
			return get_account();
		}
	});
}

std::string json_manager::connect() {
	return call([&]{
		impl_->load_channels();
		for(auto&& v : impl_->connections()) {
			v->connect();
		}
		return std::string("{}");
	});
}

std::string json_manager::disconnect() {
	return call([&]{
		for(auto&& v : impl_->connections()) {
			v->disconnect();
		}
		return std::string("{}");
	});
}

std::string json_manager::get_contacts(std::string_view const& arg) const {
	return call([&]{
		if(!arg.empty()) {
			LOG_WARN("json_manager::get_contacts not implement for non-empty argument");
			return error_to_json(make_error(errc::not_implemented));
		}
		auto contacts = impl_->contacts().enumerate();
		json::array json_c;
		for(auto& v : contacts) {
			std::string key_id = v->id().public_key_id().in_hex();
			json_c.push_back(json::object{{"name", v->name()}, {"id", key_id}});
		}
		json::object ret{{"data", json_c}};
		return json::serialize(ret);
	});
}

std::string json_manager::add_contact(std::string_view const& arg) {
	return call([&]{
		json::object obj = json::parse(arg).as_object();
		auto name = extract<std::string>(obj, "name");
		auto key_id_string = extract<std::string>(obj, "id");

		crypto::public_key_id key_id{key_id_string};

		if(impl_->contacts().find(key_id)) {
			LOG_INFO("Already have contact with key id %", key_id.in_hex());
			return error_to_json(make_error(errc::invalid_state, "Contact with given key id already exists"));
		}

		auto opt_key = impl_->query_key(impl_->extract_key_host_port(obj), key_id);
		if(!opt_key) {
			LOG_INFO("No public key found when adding contact [name=%, key_id=%]", name, key_id.in_hex());
			return error_to_json(make_error(crypto::errc::no_such_key, "Could not find requested public key for contact"));
		}
		impl_->context().public_keys().insert(*opt_key);
		auto contact = impl_->contacts().add(user_id{key_id});
		contact->set_name(name);
		auto kid = key_id.in_hex();
		return json::serialize(json::object{{"name", name}, {"id", kid}});
	});
}

std::string json_manager::get_chats(std::string_view const&) const {
	LOG_TRACE("json_manager::get_chats");
	return call([&]{

		// first load channels so that we have all the info we need to enumerate them
		impl_->load_channels();

		json::array arr;
		for(auto const& c : impl_->connections()) {
			for(auto const& c_id : c->channel_ids()) {
				channel& ch = c->get(c_id);
				arr.push_back(json::object{{"name", ch.name()}, {"id", to_hex(ch.id())}});
			}
		}
		return json::serialize(json::object{{"data", arr}});
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

		auto hp = impl_->channel_ids().find_server(cid);
		if(!hp) {
			return error_to_json(make_error(errc::no_such_data, "could not find chat"));
		}

		auto conn = impl_->load(*hp);
		auto& channel = conn->get(cid);

		json::array m_arr;
		for(auto m : channel.messages()) {
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

		auto mid = channel.send_message(message);
		return json::serialize(json::object{{"id", mid.to_hex()}});
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

void json_manager::close() {

}

}