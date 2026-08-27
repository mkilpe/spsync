#ifndef GROUPCHAT_CORE_CHANNEL_HEADER
#define GROUPCHAT_CORE_CHANNEL_HEADER

#include "chat_conn_context.hpp"
#include "message.hpp"
#include "message_storage.hpp"

#include <spsync/client/client_sync.hpp>
#include <spsync/core/sync_mode.hpp>

namespace securepath::groupchat {

class groupchat;

/**
 * The storage modes every chat channel operates with; the storage is created with these and
 * every joining client states them as its expectation. Chats run in the weak
 * require_special_seen mode (plan 1.6/Q1): messages are new object ids and never conflict
 * with each other, while membership/key changes are special records the server serialises -
 * a message that has not seen the newest membership change is rebased once by the engine.
 */
inline sync::storage_modes channel_storage_modes() {
	return {sync::sync_mode::require_special_seen, sync::auth_mode::sign_records};
}

class channel : public sync::client_sync
{
public:
	channel(chat_conn_context& context, chat_id const&);
	~channel();

	std::string name() const;

	/// data that is set when creating the chat
	void set_data(std::string name, users members);

	/// data that is set when joining chat
	void set_join_data(sync::client::storage_info const& sinfo, std::string const& name);

	void create_initial_record();
	message send_message(std::string const& message);
	std::deque<message> messages(message_search = {}) const;

	chat_id id() const;
	sync::client::storage_info storage_info() const;
private:
	channel(chat_conn_context& context, chat_id const&, database::connection_ptr);

	void on_data_change(sync::record_handle, std::deque<sync::single_data_change>) override;
	void on_user_change(sync::record_handle, sync::user_change) override;

private:
	mutable std::mutex mutex_;
	chat_conn_context& ccontext_;
	chat_id const chat_id_;
	users initial_members_;
	message_storage messages_;
	database::connection_ptr db_;
	crypto::public_key_id const my_key_id_;
};

}

#endif