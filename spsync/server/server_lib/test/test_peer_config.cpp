// SPDX-License-Identifier: MIT

#include <securepath/test_frame/test_suite.hpp>
#include <securepath/test_frame/test_utils.hpp>

#include <spsync/server/server_lib/peer_config.hpp>

#include <securepath/util/command_parser.hpp>
#include <securepath/util/conversions.hpp>

#include <sstream>

namespace securepath::sync {
namespace {

crypto::public_key_id test_key_id(std::uint8_t filler) {
	return crypto::public_key_id{octet_vector(32, filler)};
}

peer_config parse_peer(std::string const& str) {
	std::istringstream in(str);
	peer_config p;
	REQUIRE(in >> p);
	return p;
}

bool parse_fails(std::string const& str) {
	std::istringstream in(str);
	peer_config p;
	return !(in >> p);
}

}

TEST_CASE("peer_config parsing", "[unit]") {
	auto const key = test_key_id(0xab);

	auto p = parse_peer("example.com:4711/" + key.in_hex());
	CHECK(p.host == "example.com");
	CHECK(p.port == 4711);
	CHECK(p.key == key);

	// round trip through the printed form
	CHECK(parse_peer(to_string(p)) == p);

	// IPv6 hosts use brackets
	auto p6 = parse_peer("[::1]:80/" + key.in_hex());
	CHECK(p6.host == "::1");
	CHECK(p6.port == 80);
	CHECK(parse_peer(to_string(p6)) == p6);

	CHECK(parse_fails("example.com:4711"));            // no key id
	CHECK(parse_fails("example.com/" + key.in_hex())); // no port
	CHECK(parse_fails(":4711/" + key.in_hex()));       // no host
	CHECK(parse_fails("example.com:0/" + key.in_hex()));
	CHECK(parse_fails("example.com:65536/" + key.in_hex()));
	CHECK(parse_fails("example.com:x/" + key.in_hex()));
	CHECK(parse_fails("example.com:4711/nothex"));
	CHECK(parse_fails("example.com:4711/"));
}

TEST_CASE("peer_config from config file options", "[unit]") {
	auto const k1 = test_key_id(1);
	auto const k2 = test_key_id(2);

	std::string server_id;
	std::vector<peer_config> peers;
	command_parser parser;
	parser.add(server_id, "server_id", "", "");
	parser.add(peers, "peers", "", "");

	parser.parse("--server_id " + k1.in_hex()
		+ "\n--peers one:1/" + k1.in_hex() + " two:2/" + k2.in_hex() + "\n");

	CHECK(server_id == k1.in_hex());
	REQUIRE(peers.size() == 2);
	CHECK(peers[0] == parse_peer("one:1/" + k1.in_hex()));
	CHECK(peers[1] == parse_peer("two:2/" + k2.in_hex()));

	CHECK_THROWS(parser.parse("--peers bad-entry"));
}

TEST_CASE("resolve_server_identity", "[unit]") {
	auto const own = test_key_id(1);
	auto const other = test_key_id(2);
	auto const third = test_key_id(3);
	auto const own_peer = parse_peer("one:1/" + own.in_hex());
	auto const other_peer = parse_peer("two:2/" + other.in_hex());
	auto const third_peer = parse_peer("three:3/" + third.in_hex());

	{ // no configuration and no key: empty identity
		auto identity = resolve_server_identity("", {}, crypto::public_key_id{});
		CHECK(!identity.server_id.is_valid());
		CHECK(identity.peers.empty());
	}
	{ // identity derived from the key, own entry dropped from a shared peer list
		auto identity = resolve_server_identity("", {own_peer, other_peer, third_peer}, own);
		CHECK(identity.server_id == own);
		CHECK(identity.peers == std::vector{other_peer, third_peer});
	}
	{ // configured id must match the actual key
		auto identity = resolve_server_identity(own.in_hex(), {other_peer}, own);
		CHECK(identity.server_id == own);
		CHECK_THROWS(resolve_server_identity(other.in_hex(), {}, own));
		CHECK_THROWS(resolve_server_identity("nothex", {}, own));
	}
	// identity configuration without a server key is refused
	CHECK_THROWS(resolve_server_identity(own.in_hex(), {}, crypto::public_key_id{}));
	CHECK_THROWS(resolve_server_identity("", {other_peer}, crypto::public_key_id{}));
	// duplicate and invalid peer keys are refused
	CHECK_THROWS(resolve_server_identity("", {other_peer, parse_peer("dup:4/" + other.in_hex())}, own));
	CHECK_THROWS(resolve_server_identity("", {peer_config{"empty", 1, {}}}, own));
}

TEST_CASE("replicating_peers", "[unit]") {
	auto const k2 = test_key_id(2);
	auto const k3 = test_key_id(3);
	auto const other_peer = parse_peer("two:2/" + k2.in_hex());
	auto const third_peer = parse_peer("three:3/" + k3.in_hex());
	std::vector const known{other_peer, third_peer};

	// an empty subset means every known peer
	CHECK(replicating_peers({}, known) == known);
	CHECK(replicating_peers({k3}, known) == std::vector{third_peer});
	CHECK(replicating_peers({k3, k2}, known) == std::vector{third_peer, other_peer});
	// a subset id that is not a known peer is a configuration error
	CHECK_THROWS(replicating_peers({test_key_id(9)}, known));
}

}
