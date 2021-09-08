
#include "json_manager.hpp"

#include <groupchat/core/groupchat.hpp>
#include <groupchat/core/events.hpp>
#include <spsync/core/types.hpp>
#include <spsync/util/object_id.hpp>
#include <securepath/event_system/event_loop.hpp>

namespace securepath::groupchat::json_protocol {

struct json_manager::impl :  public event_system::event_handler, public groupchat {
public:
	impl(event_system::event_loop& loop, std::function<void(std::string)> func)
	: event_handler(loop)
	, groupchat(*this, groupchat_config{})
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
: impl_(std::make_unique<impl>(loop_, std::move(func)))
{
}

json_manager::~json_manager()
{
}

std::string json_manager::process(std::string cmd) {
	return cmd;
}

void json_manager::close() {

}

}