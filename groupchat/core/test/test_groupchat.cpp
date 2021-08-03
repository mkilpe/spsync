#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/test/test_server_runner.hpp>
#include <securepath/network/test/support/testing_context.hpp>


namespace securepath::groupchat::test {

TEST_CASE("groupchat_test", "[system]") {
	network::test::testing_context net_context;
	net_context.set_server_dh_parameters();
	net_context.set_server_pk_parameters();
	net_context.set_client_dh_parameters();
	net_context.set_client_pk_parameters();

	sync::test::test_server server(net_context.server_context);
	server.run();
	std::this_thread::sleep_for(1s);
}

}