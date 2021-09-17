#include <groupchat/json_protocol/json_manager.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

namespace securepath::groupchat::json_protocol::test {

TEST_CASE("json_manager_test", "[system]") {
	json_manager manager([](auto){});
}

}