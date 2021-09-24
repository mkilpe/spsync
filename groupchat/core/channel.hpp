#ifndef GROUPCHAT_CORE_CHANNEL_HEADER
#define GROUPCHAT_CORE_CHANNEL_HEADER

#include "chat_conn_context.hpp"
#include "message.hpp"

#include <spsync/client/client_sync.hpp>

namespace securepath::groupchat {

class groupchat;

class channel : public sync::client_sync
{
public:
	channel(chat_conn_context& context, chat_id const&);
	~channel();

	std::string name() const;

	/// data that is set when creating the chat
	void set_data(std::string name, users members);

	void create_initial_record();
	message_id send_message(std::string const& message);
	std::deque<message> messages(message_search = {}) const;

	chat_id id() const;
private:
	void on_data_change(sync::record_handle, std::deque<sync::single_data_change>) override;
	void on_user_change(sync::record_handle, sync::user_change) override;

private:
	chat_conn_context& ccontext_;
	chat_id const chat_id_;
	users initial_members_;
};

}

#endif