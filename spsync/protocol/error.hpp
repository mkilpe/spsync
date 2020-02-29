#ifndef SPSYNC_PROTOCOL_ERROR_HEADER
#define SPSYNC_PROTOCOL_ERROR_HEADER

#include <securepath/util/error.hpp>

namespace securepath::sync::protocol {

enum class errc {
	record_already_committed = 1,
	invalid_record,
	conflicting_record,
	record_out_of_sync,
	end_of_list
};

class spsync_category : public std::error_category {
public:
	virtual char const* name() const noexcept;
	virtual std::error_condition default_error_condition(int ev) const noexcept;
	virtual bool equivalent(std::error_code const& code, int condition) const noexcept;
 	virtual std::string message(int ev) const;
};

std::error_condition make_error_condition(errc e);
std::error_code make_error_code(errc e);
error make_error(errc e, std::string msg = "");

}

namespace std {

	template<>
	struct is_error_condition_enum<securepath::sync::protocol::errc>
		: public true_type {};
	template<>
	struct is_error_code_enum<securepath::sync::protocol::errc>
		: public true_type {};
}

#endif