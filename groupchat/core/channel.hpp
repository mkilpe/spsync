#ifndef GROUPCHAT_CORE_CHANNEL_HEADER
#define GROUPCHAT_CORE_CHANNEL_HEADER

namespace securepath::groupchat {

class channel
: public network::encrypted_net_base
, public sync::engine_output
{
public:
	channel(network::context& context, event_system::event_loop& eloop, groupchat_config conf);

private:
	network::context context_;

	sync::network_connection net_;

	dummy_progress progress_;

	database::connection_ptr database_;
	sync::record_storage storage{database_};
	sync::encryption_key_storage enc_keys{database_};

	std::unique_ptr<sync::sync_engine> engine_;
};

}

#endif