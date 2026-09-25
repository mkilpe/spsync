#pragma once

#include "chat_conn_context.hpp"
#include "file_storage.hpp"
#include "message.hpp"
#include "message_storage.hpp"

#include <spsync/client/client_sync.hpp>
#include <spsync/core/sync_mode.hpp>

#include <filesystem>
#include <optional>

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
	/// the directory of the chat's shared file data (shared_files.txt SF-D4)
	static std::string data_path(chat_conn_context const&, chat_id const&);

	/// data that is set when creating the chat
	void set_data(std::string name, users members);

	/// data that is set when joining chat
	void set_join_data(sync::client::storage_info const& sinfo, std::string const& name);

	void create_initial_record();
	message send_message(std::string_view message);
	std::deque<message> messages(message_search = {}) const;

	/// share a file with the chat (shared_files.txt): the source streams from the path
	file_entry share_file(std::filesystem::path const&, std::string name, std::string mime);
	/// the shared files of the chat with their transfer state
	std::deque<file_entry> files(file_search = {});
	std::optional<file_entry> file(file_id const&);
	/// fetch the data of a shared file; nothing is fetched unasked (SF-D3)
	void fetch_file(file_id const&);
	/// write the plaintext of a fetched file to the path
	void save_file(file_id const&, std::filesystem::path const&);
	/// let the local copy of the data go; the share stays (SF-D4)
	void remove_file(file_id const&);

	chat_id id() const;
	sync::client::storage_info storage_info() const;
private:
	channel(chat_conn_context& context, chat_id const&, database::connection_ptr);

	void on_data_change(sync::record_handle, std::deque<sync::single_data_change>) override;
	void on_user_change(sync::record_handle, sync::user_change) override;
	void on_record_rejected(sync::record_handle, error) override;
	void on_anchor_mismatch(sync::chain_block) override;
	void on_data_state_changed(sync::data_id, sync::record_data_state) override;
	void on_data_transfer_failed(sync::data_id, error) override;

	/// requires the mutex: a message of an incoming record
	void add_message(sync::single_data_change const&);
	/// requires the mutex: a share of an incoming record
	void add_file(sync::single_data_change const&, stored_file const&);
	/// requires the mutex: the data of a stored share, none when it is not there
	sync::record_data_handle data_of(file_storage::row const&);
	/// requires the mutex: the entry of a stored share with its state read off the data
	file_entry entry_of(file_storage::row const&);
	file_storage::row stored_row(file_id const&) const;
	bool own(stored_file const&) const;

private:
	mutable std::mutex mutex_;
	chat_conn_context& ccontext_;
	chat_id const chat_id_;
	users initial_members_;
	message_storage messages_;
	file_storage files_;
	database::connection_ptr db_;
	std::string db_path_;
	crypto::public_key_id const my_key_id_;
};

}

