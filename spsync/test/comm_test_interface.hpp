#pragma once

#include <spsync/comm/interface.hpp>

#include <memory>
#include <vector>
#include <spsync/util/move_only_function.hpp>

namespace securepath::sync::test {

/**
 * The test implementation of comm_input interface for engine unit tests
 */
class comm_test_interface : public comm_input {
public:
	/// data: the record data store the engine gets through data(); none by default
	comm_test_interface(sync::progress&, record_storage&, record_data_store* data = nullptr);
	~comm_test_interface();

	void set_output(comm_output&);

public:
	// the test drive interface
	using fetch_record_sig = result<std::deque<chain_block>>(sequence_number, sequence_number);
	using fetch_data_sig = std::optional<error>(data_id const&);
	using commit_sig = result<chain_block>(record_handle);
	using upload_sig = std::optional<error>(data_id const&);

	void add_fetch_records_response(move_only_function<fetch_record_sig>);
	/// the answer to the next fetch_data (it may put the data into the store first); a
	/// fetch without a queued answer stays on its way
	void add_fetch_data_response(move_only_function<fetch_data_sig>);
	void add_commit_record_response(move_only_function<commit_sig>);
	/// the answer to the next upload_data; an upload without a queued answer stays on its way
	void add_upload_data_response(move_only_function<upload_sig>);
	void add_action(move_only_function<void(comm_output&)>);

	/// every upload_data call so far, in order
	std::vector<data_id> const& upload_requests() const;

	/// every fetch_data call so far, in order
	std::vector<data_id> const& fetch_requests() const;

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
	virtual request_handle fetch_sequence_number();
	virtual request_handle fetch_records(sequence_number start, sequence_number end);
	virtual request_handle fetch_data(data_id const&);
	virtual request_handle commit_record(record_handle);
	virtual request_handle upload_data(data_id const&);
	virtual sync::progress& progress() const { return progress_; }
	virtual record_storage& records() const { return records_; }
	virtual record_data_store* data() const;

private:
	sync::progress& progress_;
	record_storage& records_;

	class impl;
	std::unique_ptr<impl> impl_;
};

}

