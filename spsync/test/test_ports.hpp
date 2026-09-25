#pragma once

#include <spsync/server/server_lib/peer_config.hpp>

#include <asio/ip/tcp.hpp>

#include <cstdint>

namespace securepath::sync::test {

/**
 * The listener ports of the tests that run servers on loopback with ports known before
 * the servers start (peers dial each other by a configured port). They lie below Linux's
 * ephemeral range (32768-60999): an outgoing connection of any process may sit on a port
 * in that range, and the test that binds it fails with "address already in use" (seen
 * 2026-09-21, todos.txt "tests"). A listener that can be found afterwards (a lone data
 * role) binds port 0 instead.
 *
 * Every test server takes a slot of its own across all test binaries, so the binaries
 * may run side by side: the slots of a file are its block below.
 */
struct test_ports {
	std::uint16_t client{};
	std::uint16_t s2s{};
	std::uint16_t data{};
};

inline constexpr std::uint16_t test_port_base = 25700;

/// the ports of the test server in the slot
inline constexpr test_ports server_ports(int slot) {
	auto const first = static_cast<std::uint16_t>(test_port_base + 4 * slot);
	return test_ports{first, static_cast<std::uint16_t>(first + 1), static_cast<std::uint16_t>(first + 2)};
}

/// the slot blocks of the test files
inline constexpr int s2s_test_slots = 0;           // test_s2s.cpp: 0-24
inline constexpr int announce_test_slots = 25;     // test_data_announce.cpp: 25-34
inline constexpr int replication_test_slots = 35;  // test_data_replication.cpp: 35-44

/// the peer entry of the test server in the slot: its s2s listener on loopback
inline peer_config peer_of(int slot, crypto::public_key_id key) {
	return peer_config{"127.0.0.1", server_ports(slot).s2s, std::move(key)};
}

/// the loopback endpoint of a port
inline asio::ip::tcp::endpoint loopback(std::uint16_t port) {
	return asio::ip::tcp::endpoint{asio::ip::address_v4::loopback(), port};
}

}
