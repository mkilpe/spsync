#pragma once

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
 * A chat created on a home server with replicas asks for weak replication (plan 4.2) so the
 * replicas carry it and a client can hop between them (plan 4.5).
 */
inline sync::storage_modes channel_storage_modes(bool replicated = false) {
	return {sync::sync_mode::require_special_seen, sync::auth_mode::sign_records,
		replicated ? sync::replication_mode::weak : sync::replication_mode::none};
}

class channel : public sync::client_sync
{
public:
	channel(chat_conn_context& context, chat_id const&);
	~channel();

	std::string name() const;

	/// the sqlite file of the chat's local storage
	std::string db_path() const { return db_path_; }
	static std::string db_path(chat_conn_context const&, chat_id const&);

	/// data that is set when creating the chat
	void set_data(std::string name, users members);

	/// data that is set when joining chat
	void set_join_data(sync::client::storage_info const& sinfo, std::string const& name);

	void create_initial_record();
	message send_message(std::string_view message);
	std::deque<message> messages(message_search = {}) const;

	chat_id id() const;
	sync::client::storage_info storage_info() const;
private:
	channel(chat_conn_context& context, chat_id const&, database::connection_ptr);

	void on_data_change(sync::record_handle, std::deque<sync::single_data_change>) override;
	void on_user_change(sync::record_handle, sync::user_change) override;
	void on_record_rejected(sync::record_handle, error) override;
	void on_anchor_mismatch(sync::chain_block) override;

private:
	mutable std::mutex mutex_;
	chat_conn_context& ccontext_;
	chat_id const chat_id_;
	users initial_members_;
	message_storage messages_;
	database::connection_ptr db_;
	std::string db_path_;
	crypto::public_key_id const my_key_id_;
};

}

