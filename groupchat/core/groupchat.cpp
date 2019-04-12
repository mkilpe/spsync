#include "groupchat.hpp"

#include <spsync/engine/sync_engine.hpp>

namespace securepath::groupchat {

// key for the message metadata
std::string const groupchat_message_id{"message"};


struct groupchat::impl : public sync::engine_output {
	impl(groupchat_config conf)
	: conf(std::move(conf))
	{}

	virtual void on_object_data_changed(sync::record_handle rec) override {

	}

	groupchat_config conf;
	//todo: put comm layer here
	std::unique_ptr<sync::engine_input> engine;
};

groupchat::groupchat(groupchat_config conf)
: impl_(std::make_unique<impl>(std::move(conf)))
{
}

groupchat::~groupchat()
{
}

message_id groupchat::send_message(std::string const& message) {
	sync::util::metadata header;
	header.insert(groupchat_message_id, message);
	return impl_->engine->sync_object_change(sync::util::create_object_id(), std::move(header));
}

}