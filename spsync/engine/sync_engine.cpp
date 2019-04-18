#include "sync_engine.hpp"

#include <mutex>

namespace securepath::sync {

class sync_engine::impl {
public:
	impl(comm_input& comm, sync_engine_config config)
	: comm(comm)
	, config(std::move(config))
	{}

	mutable std::mutex mutex;
	comm_input& comm;
	sync_engine_config config;
	engine_output* output{};
};

sync_engine::sync_engine(comm_input& comm, sync_engine_config config)
: impl_(std::make_unique<impl>(comm, std::move(config)))
{
}

sync_engine::~sync_engine()
{
}

void sync_engine::set_output(engine_output* output) {
	std::unique_lock lock{impl_->mutex};
	impl_->output = output;
}


//--- engine_input interface, see interface.hpp

record_handle sync_engine::sync_object_change(object_id const& oid, metadata const& mdata, record_data_handle) {
	//find previous record for oid
	//find last seen record
	//create record with the information
		//encrypted header with current key
		//create record_handle
	//handle record data
	//set record state
	//push record to comm layer
	return record_handle{};
}

void sync_engine::sync_user_change(users const&, metadata const& mdata) {
	//find last seen record
	//create record with the information
		//encrypted header with current key
		//embed new encryption key?
		//create record_handle
	//set record state
	//push record to comm layer
}

void sync_engine::sync_segment_end(metadata const& mdata) {
	//find last seen record
	//create record with the information
		//encrypted header with current key
		//set the segment record tags for the segment range
		//create record_handle
	//set record state
	//push record to comm layer
}

}
