#ifndef SPSYNC_CORE_DATA_CHANGE_RECORD_HEADER
#define SPSYNC_CORE_DATA_CHANGE_RECORD_HEADER

#include "record_base.hpp"

namespace securepath::sync {

class data_change_record : public record_base {
public:
private:
	//id of the object this change affects
	object_id id_;
	encrypted_record_header<data_change_header> header_;
};

}

#endif
