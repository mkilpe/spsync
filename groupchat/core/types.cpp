// SPDX-License-Identifier: MIT

#include "types.hpp"

#include <spsync/protocol/ports.hpp>

#include <securepath/util/error.hpp>

#include <format>

namespace securepath::groupchat {
namespace {

std::uint16_t parse_port(std::string const& text) {
	bool const ok = !text.empty() && text.size() <= 5
		&& text.find_first_not_of("0123456789") == std::string::npos;
	auto const value = ok ? std::stoul(text) : 0ul;
	if(value < 1 || value > 65535) {
		throw make_error(errc::invalid_argument, std::format("invalid port '{}'", text));
	}
	return static_cast<std::uint16_t>(value);
}

/// split "host:port[:port]" into host and the trailing port strings; an IPv6 host is bracketed
std::pair<std::string, std::vector<std::string>> split_host_ports(std::string const& text) {
	std::string host;
	std::string rest;
	if(!text.empty() && text.front() == '[') {
		auto const close = text.find(']');
		if(close == std::string::npos) {
			throw make_error(errc::invalid_argument, std::format("invalid replica '{}'", text));
		}
		host = text.substr(1, close - 1);
		rest = text.substr(close + 1);
	} else {
		auto const colon = text.find(':');
		host = text.substr(0, colon);
		rest = colon == std::string::npos ? std::string{} : text.substr(colon);
	}
	std::vector<std::string> ports;
	while(!rest.empty() && rest.front() == ':') {
		auto const next = rest.find(':', 1);
		ports.push_back(rest.substr(1, next == std::string::npos ? std::string::npos : next - 1));
		rest = next == std::string::npos ? std::string{} : rest.substr(next);
	}
	if(host.empty() || !rest.empty() || ports.empty() || ports.size() > 2) {
		throw make_error(errc::invalid_argument, std::format("invalid replica '{}', expected host:syncport[:keyport]", text));
	}
	return {host, ports};
}

}

sync_replica parse_sync_replica(std::string const& text) {
	auto [host, ports] = split_host_ports(text);
	auto const sync_port = parse_port(ports[0]);
	auto const key_port = ports.size() == 2 ? parse_port(ports[1]) : sync::default_key_server_port;
	return sync_replica{host_port{host, sync_port}, host_port{host, key_port}};
}

std::string format_replica(sync_replica const& r) {
	bool const v6 = r.sync_server.host.find(':') != std::string::npos;
	return std::format("{}{}{}:{}:{}", v6 ? "[" : "", r.sync_server.host, v6 ? "]" : "",
		r.sync_server.port, r.key_server.port);
}

std::vector<host_port> sync_endpoints(std::vector<sync_replica> const& replicas) {
	std::vector<host_port> ret;
	for(auto const& r : replicas) {
		ret.push_back(r.sync_server);
	}
	return ret;
}

}
