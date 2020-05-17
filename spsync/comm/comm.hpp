#ifndef SPSYNC_COMM_COMM_HEADER
#define SPSYNC_COMM_COMM_HEADER

#include "interface.hpp"

#include <memory>

namespace securepath::sync {

/**
 * The default implementation of the comm_input interface to talk with the server
 */
class comm : public comm_input {
public:
	comm();
	~comm();

	/// Set the comm_output interface which is used to communicate with higher layer
	void set_output(comm_output&);

protected:

	// -- comm_input interface, see interface.hpp --
	virtual request_handle fetch_sequence_number();
	virtual request_handle fetch_records(sequence_number start, sequence_number end);
	virtual request_handle fetch_data(sequence_number record);
	virtual request_handle commit_record(record_handle);
	virtual sync::progress& progress();
	virtual record_storage& records();
private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif