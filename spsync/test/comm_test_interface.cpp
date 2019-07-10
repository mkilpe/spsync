#include "comm_test_interface.hpp"

namespace securepath::sync::test {

class comm_test_interface::impl {
public:
	comm_output* output{};
	sequence_number current_seq{1};
	request_handle req_handle{};

	// save per action responses
	std::deque<std::function<void()>> event_queue;
	std::deque<std::function<fetch_record_sig>> fetch_records_queue;
	std::deque<std::function<fetch_data_sig>> fetch_data_queue;
	std::deque<std::function<commit_sig>> commit_queue;

	// generic actions which are handled before the above specific ones
	std::deque<std::function<void(comm_output&)>> action_queue;
};

comm_test_interface::comm_test_interface(sync::progress& p, record_storage& s)
: progress_(p)
, records_(s)
, impl_(std::make_unique<impl>())
{
}

comm_test_interface::~comm_test_interface()
{
}

void comm_test_interface::set_output(comm_output& output) {
	impl_->output = &output;
}

void comm_test_interface::add_fetch_records_response(std::function<fetch_record_sig> f) {
	impl_->fetch_records_queue.push_back(std::move(f));
}

void comm_test_interface::add_fetch_data_response(std::function<fetch_data_sig> f) {
	impl_->fetch_data_queue.push_back(std::move(f));
}

void comm_test_interface::add_commit_record_response(std::function<commit_sig> f) {
	impl_->commit_queue.push_back(std::move(f));
}

void comm_test_interface::add_action(std::function<void(comm_output&)> f) {
	impl_->action_queue.push_back(std::move(f));
}

void comm_test_interface::process_event() {
	assert(impl_->output);
	if(!impl_->action_queue.empty()) {
		auto func = impl_->action_queue.front();
		impl_->action_queue.pop_front();
		func(*impl_->output);
	} else if(!impl_->event_queue.empty()) {
		auto func = impl_->event_queue.front();
		impl_->event_queue.pop_front();
		func();
	}
}

sequence_number comm_test_interface::current_sequence_number() const {
	return impl_->current_seq;
}

request_handle comm_test_interface::fetch_records(sequence_number start, sequence_number end) {
	request_handle ret = ++impl_->req_handle;
	impl_->event_queue.push_back([=] {
		if(!impl_->fetch_records_queue.empty()) {
			auto res = impl_->fetch_records_queue.front()(start, end);
			impl_->fetch_records_queue.pop_front();
			impl_->output->on_record_response(ret, res);
		}
	});
	return ret;
}

request_handle comm_test_interface::fetch_data(sequence_number record){
	request_handle ret = ++impl_->req_handle;
	impl_->event_queue.push_back([=] {
		if(!impl_->fetch_data_queue.empty()) {
			auto res = impl_->fetch_data_queue.front()(record);
			impl_->fetch_data_queue.pop_front();
			impl_->output->on_data_response(ret, res);
		}
	});
	return ret;
}

request_handle comm_test_interface::commit_record(record_handle record) {
	request_handle ret = ++impl_->req_handle;
	impl_->event_queue.push_back([=] {
		if(!impl_->commit_queue.empty()) {
			auto res = impl_->commit_queue.front()(record);
			impl_->commit_queue.pop_front();
			impl_->output->on_commit_response(ret, res);
		}
	});
	return ret;
}

}