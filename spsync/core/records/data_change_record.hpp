#ifndef SPSYNC_CORE_DATA_CHANGE_RECORD_HEADER
#define SPSYNC_CORE_DATA_CHANGE_RECORD_HEADER

#include "record_base.hpp"
#include "../data_change_header.hpp"

#include <deque>

namespace securepath::sync {

struct single_change {
	// id of the object this change affects
	object_id id;
	encrypted_record_header<data_change_header> header;
	serialisation::trailing_data trailing_data;

	template<typename Ar>
	void serialise(Ar& ar) {
		serialisation::sequence<Ar> seq(ar);
		seq & id & header & trailing_data;
	}
};

class data_change_record : public record_base {
public:
private:
	// this can be just a single change or aggregated multiple changes
	std::deque<single_change> changes_;
	serialisation::trailing_data trailing_data;
};

}

#endif
