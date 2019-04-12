#ifndef SPSYNC_CORE_RECORD_STORAGE_HEADER
#define SPSYNC_CORE_RECORD_STORAGE_HEADER

#include <memory>

namespace securepath::sync {

class record_handle_impl;


class record_handle {
public:

private:
	std::shared_ptr<record_handle_impl> impl_;
};

/**
 * Keeps records and their current state which is used by the comm layer and the synchroniser
 *
 */
class record_storage {
public:
	record_storage();
	~record_storage();

private:
	class impl;
	std::unique_ptr<impl> impl_;
};

}

#endif
