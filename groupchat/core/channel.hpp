#ifndef GROUPCHAT_CORE_CHANNEL_HEADER
#define GROUPCHAT_CORE_CHANNEL_HEADER

#include <spsync/comm/net_connection.hpp>
#include <spsync/core/encryption_key_storage.hpp>
#include <spsync/core/progress.hpp>
#include <spsync/engine/sync_engine.hpp>

#include <securepath/database/sqlite/connection.hpp>
#include <securepath/event_system/event_handler.hpp>

namespace securepath::groupchat {

struct dummy_progress : sync::progress {};

class channel : public sync::engine_output
{
public:
	channel(network::context& context, event_system::event_loop& eloop, database::connection_ptr db);

private:
	void on_object_data_changed(sync::record_handle rec) override;

private:
	network::context context_;

	sync::network_connection net_;

	dummy_progress progress_;

	database::connection_ptr database_;
	sync::record_storage storage_{database_};
	sync::encryption_key_storage enc_keys_{database_};

	std::unique_ptr<sync::sync_engine> engine_;
};

}

#endif