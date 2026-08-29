#pragma once

#include <securepath/util/error.hpp>
#include <spsync/util/format.hpp>

#include <optional>
#include <utility>

namespace securepath::sync::util {

/**
 * Result for operation or request, contains either error or the result data
 */
template<typename DataType>
class result {
public:
	using data_type = DataType;

	/// Construct result from the error
	result(error err = {})
	: error_(std::move(err))
	{}

	/// Construct result from the data
	result(data_type data)
	: data_(std::move(data))
	{}

	/// true if this result contains error
	bool is_error() const { return !is_data(); }

	/// true if this result has data (opposite of is_error)
	bool is_data() const { return static_cast<bool>(data_); }

	/// true if this result has data (opposite of is_error)
	explicit operator bool() const { return is_data(); }

	/// returns the error if set, otherwise default constructed error
	error get_error() const { return error_; }

	/// accessors for the contained data. Prerequisite: is_data() == true
	data_type& value() { return *data_; }
	data_type const& value() const { return *data_; }

	/// accessors for the contained data. Prerequisite: is_data() == true
	data_type* operator->() { return data_.operator->(); }
	data_type const* operator->() const { return data_.operator->(); }

private:
	// the error if this result has an error
	error error_;

	// the data in case there is no error
	std::optional<data_type> data_;
};

template<typename ResultType, typename Enum>
inline bool check_result_error(util::result<ResultType> const& res, Enum value) {
	auto err = make_error_code(value);
	bool ret = res.get_error().code() == err;
	if(!ret) {
		LOG_INFO("result error not matching [{} != {}]", util::fmt_stream(res.get_error().code()), util::fmt_stream(err));
	}
	return ret;
}

}

