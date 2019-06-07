#include "comm_test_interface.hpp"


namespace securepath::sync {

class comm_test_interface::impl {
public:
	void fetch_records(request_handle req, sequence_number start, sequence_number end) {

	}

	void fetch_data(request_handle req, sequence_number record) {

	}

	void commit_record(request_handle req, record_handle) {

	}
public:
	comm_output* output;
	sequence_number current_seq{1};
	request_handle req_handle{};
	std::deque<std::function<void()>> event_queue;
};

comm_test_interface::comm_test_interface()
: impl_(std::make_unique<impl>())
{
}

comm_test_interface::~comm_test_interface()
{
}

void comm_test_interface::set_output(comm_output& output) {
	impl_->output = &output;
}

sequence_number comm_test_interface::current_sequence_number() const {
	return impl_->current_seq;
}

request_handle comm_test_interface::fetch_records(sequence_number start, sequence_number end) {
	req handle ret = ++impl_->req_handle;
	impl_->event_queue_.push_back([=] {
		impl_->fetch_records(ret, start, end);
	});
	return ret;
}

request_handle comm_test_interface::fetch_data(sequence_number record){
	req handle ret = ++impl_->req_handle;
	impl_->event_queue.push_back([=] {
		impl_->fetch_data(ret, record);
	});
	return ret;
}

request_handle comm_test_interface::commit_record(record_handle record) {
	req handle ret = ++impl_->req_handle;
	impl_->event_queue.push_back([=] {
		impl_->commit_record(ret, record);
	});
	return ret;
}

}