#ifndef SPSYNC_ENGINE_TEST_COMM_TEST_INTERFACE_HEADER
#define SPSYNC_ENGINE_TEST_COMM_TEST_INTERFACE_HEADER

#include <spsync/comm/interface.hpp>

#include <memory>

namespace securepath::sync {

/**
 * The test implementation of comm_input interface for engine unit tests
 */
class comm_test_interface : public comm_input {
public:
	comm_test_interface();
	~comm_test_interface();

	void set_output(comm_output&);


public:
	// the test drive interface


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