#include "comm_test_interface.hpp"

namespace securepath::sync::test {

class comm_test_interface::impl {
public:
	comm_output* output{};
	sequence_number current_seq;
	octet_vector previous_block_hash;
	request_handle req_handle{};

	// save per action responses
	std::deque<std::move_only_function<void()>> event_queue;
	std::deque<std::move_only_function<fetch_record_sig>> fetch_records_queue;
	std::deque<std::move_only_function<fetch_data_sig>> fetch_data_queue;
	std::deque<std::move_only_function<commit_sig>> commit_queue;

	// generic actions which are handled before the above specific ones
	std::deque<std::move_only_function<void(comm_output&)>> action_queue;
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

void comm_test_interface::add_fetch_records_response(std::move_only_function<fetch_record_sig> f) {
	impl_->fetch_records_queue.push_back(std::move(f));
}

void comm_test_interface::add_fetch_data_response(std::move_only_function<fetch_data_sig> f) {
	impl_->fetch_data_queue.push_back(std::move(f));
}

void comm_test_interface::add_commit_record_response(std::move_only_function<commit_sig> f) {
	impl_->commit_queue.push_back(std::move(f));
}

void comm_test_interface::add_action(std::move_only_function<void(comm_output&)> f) {
	impl_->action_queue.push_back(std::move(f));
}

sequence_number comm_test_interface::next_sequence_number() {
	return ++impl_->current_seq;
}

octet_vector comm_test_interface::previous_block_hash() const {
	return impl_->previous_block_hash;
}

bool comm_test_interface::process_event() {
	bool ret = false;
	assert(impl_->output);
	if(!impl_->action_queue.empty()) {
		auto func = std::move(impl_->action_queue.front());
		impl_->action_queue.pop_front();
		func(*impl_->output);
		ret = true;
	} else if(!impl_->event_queue.empty()) {
		auto func = std::move(impl_->event_queue.front());
		impl_->event_queue.pop_front();
		func();
		ret = true;
	}
	return ret;
}

request_handle comm_test_interface::fetch_sequence_number() {
	request_handle ret = ++impl_->req_handle;
	impl_->event_queue.push_back([=, this] {
		// no identity: the owner tracking is a no-op for this harness (plan 4.5)
		impl_->output->on_sequence_number_response(ret, sequence_info{impl_->current_seq, {}});
	});
	return ret;
}

request_handle comm_test_interface::fetch_records(sequence_number start, sequence_number end) {
	request_handle ret = ++impl_->req_handle;
	impl_->event_queue.push_back([=, this] {
		if(!impl_->fetch_records_queue.empty()) {
			auto res = impl_->fetch_records_queue.front()(start, end);
			impl_->fetch_records_queue.pop_front();
			impl_->output->on_record_response(ret, record_response{end, impl_->current_seq, res});
		} else {
			LOG_TRACE("empty record queue");
		}
	});
	return ret;
}

request_handle comm_test_interface::fetch_data(sequence_number record){
	request_handle ret = ++impl_->req_handle;
	impl_->event_queue.push_back([=, this] {
		if(!impl_->fetch_data_queue.empty()) {
			auto res = impl_->fetch_data_queue.front()(record);
			impl_->fetch_data_queue.pop_front();
			impl_->output->on_data_response(ret, res);
		} else {
			LOG_TRACE("empty fetch queue");
		}
	});
	return ret;
}

request_handle comm_test_interface::commit_record(record_handle record) {
	request_handle ret = ++impl_->req_handle;
	impl_->event_queue.push_back([=, this] {
		if(!impl_->commit_queue.empty()) {
			auto res = impl_->commit_queue.front()(record);
			impl_->commit_queue.pop_front();
			if(res) {
				impl_->previous_block_hash = res->hash();
			}
			impl_->output->on_commit_response(ret, commit_response{impl_->current_seq, res});
		} else {
			LOG_TRACE("empty commit queue");
		}
	});
	return ret;
}

}