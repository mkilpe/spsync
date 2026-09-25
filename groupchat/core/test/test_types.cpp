// SPDX-License-Identifier: MIT

#include <groupchat/core/types.hpp>

#include <spsync/protocol/ports.hpp>

#include <securepath/test_frame/test_suite.hpp>

namespace securepath::groupchat::test {

// replicas of the home server are given as host:syncport[:keyport] (plan 4.5)
TEST_CASE("sync replica parsing", "[unit]") {
	auto r = parse_sync_replica("replica.example:18210:18198");
	CHECK(r.sync_server == host_port{"replica.example", 18210});
	CHECK(r.key_server == host_port{"replica.example", 18198});
	CHECK(format_replica(r) == "replica.example:18210:18198");

	auto d = parse_sync_replica("127.0.0.1:18210");
	CHECK(d.sync_server == host_port{"127.0.0.1", 18210});
	CHECK(d.key_server == host_port{"127.0.0.1", sync::default_key_server_port});

	auto v6 = parse_sync_replica("[::1]:18210:18198");
	CHECK(v6.sync_server == host_port{"::1", 18210});
	CHECK(format_replica(v6) == "[::1]:18210:18198");

	CHECK_THROWS(parse_sync_replica("nohost"));
	CHECK_THROWS(parse_sync_replica(":18210"));
	CHECK_THROWS(parse_sync_replica("host:0"));
	CHECK_THROWS(parse_sync_replica("host:1:2:3"));
	CHECK_THROWS(parse_sync_replica("host:abc"));
	CHECK_THROWS(parse_sync_replica("[::1:18210"));

	CHECK(sync_endpoints({r, d}) == std::vector<host_port>{r.sync_server, d.sync_server});
}

}
