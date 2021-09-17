
#include "json_manager.hpp"
#include "json_helpers.hpp"

#include <groupchat/core/groupchat.hpp>
#include <groupchat/core/events.hpp>
#include <spsync/core/types.hpp>
#include <spsync/util/object_id.hpp>
#include <securepath/event_system/event_loop.hpp>

#include <securepath/log/backend/backend.hpp>
#include <securepath/log/backend/file_output.hpp>

namespace securepath::groupchat::json_protocol {

void initialise_logging() {
	log::backend::add_backend<log::backend::file_output>("file", "gc.log");
	LOG_TRACE("logging initialised");
}

std::uint16_t const default_storage_server_port{18200};

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

	impl(event_system::event_loop& l, network::context& context, std::function<void(std::string)> func)
	: event_handler(l)
	, groupchat(*this, context, groupchat_config{})
	, notify(std::move(func))
	{}

	~impl() {
		stop_handler();
	}

	void on_connect(server_id) {

	}

	void on_disconnect(server_id, error) {

	}

	void on_create(server_id, chat_id, error) {

	}

	void on_change_user(server_id, chat_id, sync::users change, error) {

	}

	void on_join(server_id, chat_id, error) {

	}

	void on_message(server_id, chat_id, message) {

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

public:
	 std::function<void(std::string)> const notify;
};


json_manager::json_manager(std::function<void(std::string)> func)
: loop_(std::make_unique<event_system::single_thread_event_loop>())
, impl_(std::make_unique<impl>(*loop_, std::move(func)))
{
}


json_manager::json_manager(network::context& context, std::function<void(std::string)> func)
: loop_(std::make_unique<event_system::single_thread_event_loop>())
, impl_(std::make_unique<impl>(*loop_, context, std::move(func)))
{
}

json_manager::~json_manager()
{
}

//std::string json_manager::process(std::string cmd) {
//	return cmd;
//}

std::string json_manager::get_account() const {
	return call([&]{
		auto acc = impl_->account_info();
		if(acc) {
			LOG_TRACE("found account");
			json::object user{{"name", acc->name}};
			json::object ret{{"user", user}};
			return json::serialize(ret);
		} else {
			LOG_TRACE("no account found");
			return std::string("{}");
		}
	});
}

std::string json_manager::create_account(std::string const& arg) {
	LOG_TRACE("json_manager::create_account");
	return call([&]{
		auto acc = impl_->account_info();
		if(acc) {
			LOG_WARN("account already exists");
			return error_to_json(make_error(errc::invalid_state, "account already exists"));
		} else {
			json::value v = json::parse(arg);
			auto obj = v.as_object();
			auto opt_host = extract_opt<std::string>(obj, "server_host");
			auto opt_port = extract_opt<int>(obj, "server_port");
			host_port hp{opt_host.value_or("gc.securepath.fi"), static_cast<std::uint16_t>(opt_port.value_or(default_storage_server_port))};
			impl_->create_account(hp, extract<std::string>(obj, "name"));
			return get_account();
		}
	});
}

void json_manager::close() {

}

}