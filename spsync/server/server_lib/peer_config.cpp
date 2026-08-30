#include "peer_config.hpp"

#include <securepath/log/log.hpp>

#include <algorithm>
#include <format>
#include <istream>
#include <ostream>

namespace securepath::sync {
namespace {

bool parse_host(std::string str, std::string& host) {
	if(str.size() >= 2 && str.front() == '[' && str.back() == ']') {
		str = str.substr(1, str.size() - 2);
	}
	host = std::move(str);
	return !host.empty();
}

bool parse_port(std::string const& str, std::uint16_t& port) {
	bool ok = !str.empty() && str.size() <= 5
		&& str.find_first_not_of("0123456789") == std::string::npos;
	if(ok) {
		auto const value = std::stoul(str);
		ok = value >= 1 && value <= 65535;
		if(ok) {
			port = static_cast<std::uint16_t>(value);
		}
	}
	return ok;
}

bool parse_key(std::string const& hex, crypto::public_key_id& key) {
	bool ok = !hex.empty();
	if(ok) {
		try {
			key = crypto::public_key_id{hex};
		} catch(std::exception const&) {
			ok = false;
		}
	}
	return ok;
}

crypto::public_key_id parse_server_id(std::string const& hex) {
	try {
		return crypto::public_key_id{hex};
	} catch(std::exception const&) {
		throw make_error(sync::errc::invalid_configuration, "invalid server_id hex");
	}
}

}

std::istream& operator>>(std::istream& in, peer_config& p) {
	std::string s;
	if(in >> s) {
		auto const slash = s.rfind('/');
		auto const colon = slash == std::string::npos ? std::string::npos : s.rfind(':', slash);
		bool const ok = slash != std::string::npos && colon != std::string::npos
			&& parse_host(s.substr(0, colon), p.host)
			&& parse_port(s.substr(colon + 1, slash - colon - 1), p.port)
			&& parse_key(s.substr(slash + 1), p.key);
		if(!ok) {
			in.setstate(std::ios::failbit);
		}
	}
	return in;
}

std::string to_string(peer_config const& p) {
	bool const v6 = p.host.find(':') != std::string::npos;
	return std::format("{}{}{}:{}/{}", v6 ? "[" : "", p.host, v6 ? "]" : "", p.port, p.key.in_hex());
}

std::ostream& operator<<(std::ostream& out, peer_config const& p) {
	return out << to_string(p);
}

server_identity resolve_server_identity(std::string const& configured_id, std::vector<peer_config> peers,
	crypto::public_key_id const& actual) {
	if(!actual.is_valid() && (!configured_id.empty() || !peers.empty())) {
		throw make_error(sync::errc::invalid_configuration, "server identity configured without a server key");
	}
	if(!configured_id.empty() && parse_server_id(configured_id) != actual) {
		throw make_error(sync::errc::invalid_configuration, "configured server_id does not match the server key");
	}
	server_identity identity{actual, {}};
	for(auto& peer : peers) {
		if(!peer.key.is_valid()) {
			throw make_error(sync::errc::invalid_configuration, "peer without a key id");
		}
		if(peer.key == actual) {
			LOG_INFO("dropping own entry from the peer list [{}]", peer);
		} else if(std::ranges::find(identity.peers, peer.key, &peer_config::key) != identity.peers.end()) {
			throw make_error(sync::errc::invalid_configuration, "duplicate peer key id");
		} else {
			identity.peers.push_back(std::move(peer));
		}
	}
	return identity;
}

std::vector<peer_config> replicating_peers(std::vector<crypto::public_key_id> const& subset,
	std::vector<peer_config> const& known) {
	std::vector<peer_config> ret;
	if(subset.empty()) {
		ret = known;
	} else {
		for(auto const& id : subset) {
			auto const it = std::ranges::find(known, id, &peer_config::key);
			if(it == known.end()) {
				throw make_error(sync::errc::invalid_configuration, "storage peer is not a known server peer");
			}
			ret.push_back(*it);
		}
	}
	return ret;
}

}
