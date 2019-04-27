#ifndef SPSYNC_CORE_RECORD_DATA_HEADER
#define SPSYNC_CORE_RECORD_DATA_HEADER

#include <spsync/core/types.hpp>

#include <memory>

namespace securepath::sync {

/// State of the record data
enum class record_data_state {
	unknown = 0,

	/// data not requested
	deferred,

	/// there are still data to be uploaded
	upload_pending,

	/// there are still data to be downloaded
	download_pending,

	/// we have all the data
	in_sync,

	/// the data was removed and has to be re-queried if needed
	removed,

	/// the data is invalid, e.g. the aes gcm tag didn't match
	invalid
};


/**
 * Interface to a data for single record
 *
 */
class record_data {
public:

	// size
	// data blocks we have
	// read/write data (plain and encrypted?)
	// record data state

	// set state
	// remove data

private:

};

using record_data_handle = std::shared_ptr<record_data>;

/**
 * Provides the decrypted and authenticated data from the record_data
 *
 */
//class decrypted_record_data {
//public:
//};

}

#endif