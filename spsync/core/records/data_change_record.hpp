#ifndef SPSYNC_CORE_DATA_CHANGE_RECORD_HEADER
#define SPSYNC_CORE_DATA_CHANGE_RECORD_HEADER

#include "record_base.hpp"

namespace securepath::sync {

class data_change_record : public record_base {
public:
private:
	encrypted_record_header<data_change_header> header_;
};

}

#endif
