#pragma once

#include <groupchat/json_protocol/json_helpers.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::groupchat::json_protocol::test {
namespace {

bool check_contains_json(json::object const& in, json::object const& exp);

bool check_contains_json(json::array const& in, json::array const& exp) {
	for(auto it = exp.begin(); it != exp.end(); ++it) {
		bool found = false;
		for(auto sit = in.begin(); sit != in.end() && !found; ++sit) {
			if(it->is_object() && sit->is_object()) {
				found = check_contains_json(sit->as_object(), it->as_object());
			} else {
				found = *it == *sit;
			}
		}
		if(!found) {
			return false;
		}
	}
	return true;
}

bool check_contains_json(json::object const& in, json::object const& exp) {
	for(auto it = exp.begin(); it != exp.end(); ++it) {
		auto v = in.find(it->key());
		if(v == in.end() || v->value().kind() != it->value().kind()) {
			return false;
		}
		if(v->value().is_object()) {
			if(!check_contains_json(v->value().as_object(), it->value().as_object())) {
				return false;
			}
		} else if(v->value().is_array()) {
			if(!check_contains_json(v->value().as_array(), it->value().as_array())) {
				return false;
			}
		} else if(v->value() != it->value()) {
			return false;
		}
	}
	return true;
}

bool check_contains_json(std::string_view in, std::string_view exp) {
	CAPTURE(in, exp);
	auto in_j = json::parse(in).as_object();
	auto exp_j = json::parse(exp).as_object();
	return check_contains_json(in_j, exp_j);
}

bool check_equal_json(std::string_view in, std::string_view exp) {
	CAPTURE(in, exp);
	auto in_j = json::parse(in).as_object();
	auto exp_j = json::parse(exp).as_object();
	return in_j == exp_j;
}

#define CHECK_JSON(input, expect) \
	{ std::string in = input; std::string exp = expect; \
	CHECKED_ELSE(check_contains_json(in, exp)) \
		WARN(in + " not containing " + exp); }

#define REQUIRE_JSON(input, expect) \
	{ std::string in = input; std::string exp = expect; \
	CHECKED_ELSE(check_contains_json(in, exp)) \
		FAIL(in + " not containing " + exp); }

#define CHECK_EQUAL_JSON(input, expect) \
	{ std::string in = input; std::string exp = expect; \
	CHECKED_ELSE(check_equal_json(in, exp)) \
		WARN(in + " not equal to " + exp); }

#define WAIT_CHECK_JSON(input, expect, time) \
	{ CHECK_NOTHROW([&]{WAIT(check_contains_json(input, expect), time);}()); \
	CHECK_JSON(input, expect); }

#define WAIT_REQUIRE_JSON(input, expect, time) \
	{ CHECK_NOTHROW([&]{WAIT(check_contains_json(input, expect), time);}()); \
	REQUIRE_JSON(input, expect); }

}
}