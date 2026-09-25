// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_serialisation.hpp>

#include <spsync/util/result.hpp>

using namespace std::string_literals;

namespace securepath::sync::util {

TEST_CASE("result", "[unit]") {
	result<std::string> error_res(make_error(errc::unknown_error));
	CHECK(error_res.is_error());
	CHECK(!error_res.is_data());
	CHECK(!error_res);
	CHECK(error_res.get_error().code() == make_error_code(errc::unknown_error));

	result res("test string"s);
	CHECK(!res.is_error());
	CHECK(res.is_data());
	CHECK(res);
	CHECK(!res.get_error());
	CHECK(res.value() == "test string"s);
	CHECK(res->size() == "test string"s.size());
}

}
