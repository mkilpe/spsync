
#include "json_manager.hpp"

#include <groupchat/core/groupchat.hpp>
#include <spsync/core/types.hpp>
#include <spsync/util/object_id.hpp>
#include <securepath/event_system/event_loop.hpp>

namespace securepath::groupchat::json_protocol {

struct json_manager::impl : public groupchat {
public:
	impl(event_system::event_loop& loop, std::function<void(std::string)> func)
	: groupchat(groupchat_config{}, loop)
	, notify(std::move(func))
	{}

	void on_connect(server_id) override {

	}

	void on_disconnect(server_id, error) override {

	}

	void on_create(server_id, chat_id, error) override {

	}

	void on_change_user(server_id, chat_id, sync::users change, error) override {

	}

	void on_join(server_id, chat_id) override {

	}

	void on_message(server_id, chat_id, message) override {

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