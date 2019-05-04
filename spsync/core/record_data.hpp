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

	/// the data is not yet complete on the remote side
	remote_not_complete,

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
	virtual ~record_data() = default;

	/// Local record data id which is used to relate the data to the record structure in database
	virtual std::uint64_t local_id() const = 0;

	/**
	 * Returns the size of the data.
	 * This function returns the logical size of this data, it does not related to the data we currently
	 *  have available. For that, use \ref available_size
	 */
	virtual std::uint64_t size() const = 0;

	/// Size of the data that is available for use and can be read out.
	virtual std::uint64_t available_size() const = 0;

	/// Read octets out of the record data with given offset
	virtual std::uint64_t read(std::uint64_t offset, std::uint8_t* buffer, std::uint64_t size) = 0;

	/// Write octets to the record data
	virtual std::uint64_t write(std::uint64_t offset, std::uint8_t const* buffer, std::uint64_t size) = 0;

	/// State of this data record
	virtual record_data_state state() const = 0;

	/// Set the state of this data record
	virtual void set_state(record_data_state) = 0;

	/// Remove the stored data, after this available_size() == 0 and the data has to be re-queried if needed
	virtual void remove_data() = 0;
};

using record_data_handle = std::shared_ptr<record_data>;
using const_record_data_handle = std::shared_ptr<record_data const>;

}

#endif