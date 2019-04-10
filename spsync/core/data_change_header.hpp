#ifndef SPSYNC_CORE_DATA_CHANGE_HEADER_HEADER
#define SPSYNC_CORE_DATA_CHANGE_HEADER_HEADER

#include <spsync/core/types.hpp>

namespace securepath::sync {

/**
 * Contains the information about the data for a change
 */
struct data_change_info {
	// size of the changed data, can't be bigger than (2^39)-256 bits (64 GiB) due to AES GCM mode
	std::uint64_t size{};

	// iv for encrypting the change data
	octet_vector iv;

	// AES GCM tag over the change data
	octet_vector gcm_tag;

	serialisation::trailing_data trailing_data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & size & iv & gcm_tag & trailing_data;
	}
};

/**
 * This is the encrypted header in the data_change_record
 *
 */
class data_change_header {
public:

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & data_change_ & metadata_ & trailing_data_;
	}
private:
	// contains the information about the data for the change if there is any
	std::optional<data_change_info> data_change_;

	// arbitrary metadata for higher layers
	util::metadata metadata_;
	serialisation::trailing_data trailing_data_;
};

}

#endif