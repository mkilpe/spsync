#pragma once

#include "../types.hpp"
#include <spsync/core/data/data_descriptor.hpp>
#include <spsync/util/metadata.hpp>

namespace securepath::sync {

/**
 * This is the encrypted header in the data_change_record
 *
 */
class data_change_header {
public:
	data_change_header() {}
	data_change_header(util::metadata meta, std::optional<data_header> data = std::nullopt)
	: creation_time_(clock_type::now())
	, data_(std::move(data))
	, metadata_(std::move(meta))
	{}

	/// get the time when this change was created
	time_point creation_time() const { return creation_time_; }

	/// the members-only half of the data descriptor (RD2) if the change carries data
	std::optional<data_header> data_info() const { return data_; }

	/// get the arbitrary metadata
	util::metadata metadata() const { return metadata_; }

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & creation_time_ & data_ & metadata_ & trailing_data_;
	}
private:
	// time when this change was created
	time_point creation_time_;

	// the encrypted half of the data descriptor, when the change has data
	std::optional<data_header> data_;

	// arbitrary metadata for higher layers
	util::metadata metadata_;
	serialisation::trailing_data trailing_data_;
};

}
