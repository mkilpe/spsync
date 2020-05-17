#include "comm.hpp"

#include <securepath/network/encryption/encrypted_connection.hpp>

namespace securepath::sync {

struct comm::impl {
	impl()
	{}

	comm_output* output{};
};

comm::comm()
: impl_(std::make_unique<impl>())
{
}

comm::~comm()
{
}

void comm::set_output(comm_output& out) {
	impl_->output = &out;
}

request_handle comm::fetch_sequence_number() {
	assert(0);
	return request_handle{};
}

request_handle comm::fetch_records(sequence_number start, sequence_number end) {
	assert(0);
	return request_handle{};
}

request_handle comm::fetch_data(sequence_number record) {
	assert(0);
	return request_handle{};
}

request_handle comm::commit_record(record_handle) {
	assert(0);
	return request_handle{};
}

sync::progress& comm::progress() {
	assert(0);
}

record_storage& comm::records() {
	assert(0);
}

}
