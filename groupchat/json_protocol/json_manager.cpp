
#include "json_manager.hpp"
#include "json.hpp"

#include <groupchat/core/groupchat.hpp>
#include <groupchat/core/events.hpp>
#include <spsync/core/types.hpp>
#include <spsync/util/object_id.hpp>
#include <securepath/event_system/event_loop.hpp>

namespace securepath::groupchat::json_protocol {

std::uint16_t const default_storage_server_port{18200};

struct json_manager::impl
	: public event_system::event_handler
	, public groupchat
{
public:
	impl(std::unique_ptr<event_system::event_loop> loop, std::function<void(std::string)> func)
	: event_handler(*loop)
	, groupchat(*this, groupchat_config{})
	, notify(std::move(func))
	, loop(std::move(loop))
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
	 std::unique_ptr<event_system::event_loop> loop;
};


json_manager::json_manager(std::function<void(std::string)> func)
: impl_(std::make_unique<impl>(std::make_unique<event_system::single_thread_event_loop>(), std::move(func)))
{
}

json_manager::~json_manager()
{
}

 //{"error": {"code": 10001, "message": "msg"}}
static std::string error_to_json(securepath::error const& err) {
	json::object error{
			{"code", err.code().value()},
			{"message", err.code().message()},
			{"aux_message", err.message()}};
	json::object ret{{"error", error}};
	return json::serialize(ret);
}

static std::string call(auto Func) {
	try {
		return Func();
	} catch(securepath::error const& err) {
		return error_to_json(err);
	} catch(std::exception const& exp) {
		return error_to_json(make_error(errc::exception_occurred, exp.what()));
	} catch(...) {
		return error_to_json(make_error(errc::exception_occurred, "Unknown exception"));
	}
}

template<class T>
T extract(json::object const& obj, std::string_view key) {
	return json::value_to<T>(obj.at(key));
}

//std::string json_manager::process(std::string cmd) {
//	return cmd;
//}

std::string json_manager::get_account() const {
	return call([&]{
		auto acc = impl_->account_info();
		if(acc) {
			json::object user{{"name", acc->name}};
			json::object ret{{"user", user}};
			return json::serialize(ret);
		} else {
			return std::string("{}");
		}
	});
}

std::string json_manager::create_account(std::string const& arg) {
	return call([&]{
		auto acc = impl_->account_info();
		if(acc) {
			return error_to_json(make_error(errc::invalid_state, "account already exists"));
		} else {
			json::value v = json::parse(arg);
			impl_->create_account(host_port{"127.0.0.1", default_storage_server_port}
				, extract<std::string>(v.as_object(), "name"));
			return get_account();
		}
	});
}

void json_manager::close() {

}

}