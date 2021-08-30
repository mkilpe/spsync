#ifndef GROUPCHAT_CORE_CHANNEL_HEADER
#define GROUPCHAT_CORE_CHANNEL_HEADER

#include "types.hpp"

#include <spsync/comm/net_connection.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/engine/sync_engine.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/event_system/event_handler.hpp>

namespace securepath::groupchat {

/// associate object id to a message
using message_id = sync::util::object_id;

struct dummy_progress : sync::progress {
	dummy_progress(event_system::event_loop& eloop) : progress(eloop) {}
    void handle_event(std::unique_ptr<event_system::event_base>) override {}
};

class groupchat;

class channel : public sync::engine_output
{
public:
	channel(server_id sid, event_system::event_handler& callback, network::context& context, chat_id const&);

	void set_name(std::string name);
	void init(sync::network_connection& conn);

	message_id send_message(std::string const& message);
	void change_user(sync::users change);

	void create_initial_record();
private:
	void on_object_data_changed(sync::record_handle) override;
	void on_user_changed(sync::record_handle) override;

private:
	event_system::event_handler& callback_;
	network::context& context_;
	server_id const sid_;
	chat_id const chat_id_;
	std::string name_;

	dummy_progress progress_;

	database::connection_ptr database_;
	std::unique_ptr<sync::record_storage> storage_;
	std::unique_ptr<sync::encryption_key_storage> enc_keys_;
	std::unique_ptr<sync::crypto_context> crypto_;

	std::unique_ptr<sync::sync_engine> engine_;
};

}

#endif