#include "sync_engine.hpp"

#include <mutex>

namespace securepath::sync {

class sync_engine::impl {
public:
	impl(comm_input& comm, sync_engine_config config)
	: comm(comm)
	, records(comm.records())
	, config(std::move(config))
	{}

	//template<typename Header>
	//encrypted_record_header<Header> encrypt_header(Header const& header) {
		//find current encryption key
		//create iv
		//use aes-gcm to encrypt the serialised header
	//	return {};
	//}

	mutable std::mutex mutex;
	comm_input& comm;
	record_storage& records;
	sync_engine_config config;
	engine_output* output{};
	sequence_number last_seen_sequence;
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

//f: for now just implement plain record without data
record_handle sync_engine::sync_object_change(object_id const& oid, metadata const& mdata, record_data_handle) {
	//auto last_oid_record = impl_->records.find_last(oid);
	//auto last_record = impl_->records.find_last();

	//data_change_header header{mdata};


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
