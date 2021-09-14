#ifndef GROUPCHAT_CORE_CHANNEL_HEADER
#define GROUPCHAT_CORE_CHANNEL_HEADER

#include "types.hpp"

#include <spsync/client/client_sync.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/event_system/event_handler.hpp>

namespace securepath::groupchat {

/// associate object id to a message
using message_id = sync::util::object_id;

class groupchat;

class channel : public sync::client_sync
{
public:
	channel(server_id sid, event_system::event_handler& callback, network::context& context, chat_id const&);
	~channel();

	void set_name(std::string name);

	void create_initial_record();
	message_id send_message(std::string const& message);

	chat_id id() const;
private:
	void on_data_change(sync::record_handle, std::deque<sync::single_data_change>) override;
	void on_user_change(sync::record_handle, sync::user_change) override;

private:
	event_system::event_handler& callback_;
	network::context& context_;
	server_id const sid_;
	chat_id const chat_id_;
};

}

#endif