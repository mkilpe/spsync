#include <groupchat/json_protocol/json_helpers.hpp>
#include <groupchat/json_protocol/json_manager.hpp>
#include <groupchat/core/groupchat.hpp>

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/test/test_server_runner.hpp>
#include <securepath/network/test/support/testing_context.hpp>

#include <iostream>

namespace securepath::groupchat::json_protocol::test {

TEST_CASE("json_manager_test", "[system]") {
	std::remove(groupchat_config{}.db.c_str());

	network::test::testing_context net_context;
	net_context.set_server_dh_parameters();
	net_context.set_server_pk_parameters();
	net_context.set_client_dh_parameters();
	net_context.set_client_pk_parameters();

	sync::test::test_server server(net_context.server_context);
	server.run();
	std::this_thread::sleep_for(1s);

	{
		json_manager manager(net_context.client_context, [](auto){});
		CHECK(json::parse(manager.get_account()).as_object() == json::object{});
		{
			auto res = json::parse(manager.create_account(R"sss({"name": "test", "server_host": "127.0.0.1"})sss"));
			CHECK(extract<json::object>(res.as_object(), "user") == json::object{{"name", "test"}});
		}
		auto res = json::parse(manager.get_account());
		CHECK(extract<json::object>(res.as_object(), "user") == json::object{{"name", "test"}});
	}
	{
		json_manager manager(net_context.client_context, [](auto){});
		auto res = json::parse(manager.get_account());
		CHECK(extract<json::object>(res.as_object(), "user") == json::object{{"name", "test"}});
	}
}

}