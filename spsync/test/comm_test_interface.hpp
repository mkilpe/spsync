#ifndef SPSYNC_TEST_COMM_TEST_INTERFACE_HEADER
#define SPSYNC_TEST_COMM_TEST_INTERFACE_HEADER

#include <spsync/comm/interface.hpp>

#include <memory>

namespace securepath::sync::test {

/**
 * The test implementation of comm_input interface for engine unit tests
 */
class comm_test_interface : public comm_input {
public:
	comm_test_interface(sync::progress&, record_storage&);
	~comm_test_interface();

	void set_output(comm_output&);

public:
	// the test drive interface
	using fetch_record_sig = result<std::deque<chain_block>>(sequence_number, sequence_number);
	using fetch_data_sig = result<record_data_handle>(sequence_number);
	using commit_sig = result<chain_block>(record_handle);

	void add_fetch_records_response(std::function<fetch_record_sig>);
	void add_fetch_data_response(std::function<fetch_data_sig>);
	void add_commit_record_response(std::function<commit_sig>);
	void add_action(std::function<void(comm_output&)>);

	sequence_number next_sequence_number();
	octet_vector previous_block_hash() const;

	bool process_event();
	bool process_events() {
		bool res = false;
		while(process_event()) {
			res = true;
		}
		return res;
	}

public:
	// -- comm_input interface, see interface.hpp --
	virtual sequence_number current_sequence_number() const;
	virtual request_handle fetch_records(sequence_number start, sequence_number end);
	virtual request_handle fetch_data(sequence_number record);
	virtual request_handle commit_record(record_handle);
	virtual sync::progress& progress() { return progress_; }
	virtual record_storage& records() { return records_; }

private:
	sync::progress& progress_;
	record_storage& records_;

	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif