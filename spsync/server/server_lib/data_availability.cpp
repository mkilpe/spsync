// SPDX-License-Identifier: MIT

#include "data_availability.hpp"

#include <securepath/crypto/hash.hpp>

#include <algorithm>
#include <tuple>

namespace securepath::sync {

bool data_availability::announce(protocol::storage_id const& sid, data_id const& id, data_holding const& holding) {
	std::unique_lock lock{mutex_};
	auto& list = holdings_[data_key{sid, id}];
	auto it = std::ranges::find(list, holding.holder, &data_holding::holder);
	bool const was_complete = it != list.end() && it->complete;
	if(it == list.end()) {
		list.push_back(holding);
	} else {
		*it = holding;
	}
	return holding.complete && !was_complete;
}

void data_availability::forget(protocol::storage_id const& sid, data_id const& id) {
	std::unique_lock lock{mutex_};
	holdings_.erase(data_key{sid, id});
}

void data_availability::forget_holder(crypto::public_key_id const& holder) {
	std::unique_lock lock{mutex_};
	for(auto it = holdings_.begin(); it != holdings_.end();) {
		std::erase_if(it->second, [&](data_holding const& h) { return h.holder == holder; });
		it = it->second.empty() ? holdings_.erase(it) : std::next(it);
	}
}

void data_availability::set_load(crypto::public_key_id const& holder, holder_load const& load) {
	std::unique_lock lock{mutex_};
	loads_[holder] = load;
}

std::vector<data_holding> data_availability::holdings(protocol::storage_id const& sid, data_id const& id) const {
	std::unique_lock lock{mutex_};
	std::vector<data_holding> ret;
	auto it = holdings_.find(data_key{sid, id});
	if(it != holdings_.end()) {
		ret = it->second;
	}
	return ret;
}

holder_load data_availability::load(crypto::public_key_id const& holder) const {
	std::unique_lock lock{mutex_};
	holder_load ret;
	auto it = loads_.find(holder);
	if(it != loads_.end()) {
		ret = it->second;
	}
	return ret;
}

std::vector<std::pair<protocol::storage_id, data_id>> data_availability::known_data() const {
	std::unique_lock lock{mutex_};
	std::vector<std::pair<protocol::storage_id, data_id>> ret;
	ret.reserve(holdings_.size());
	for(auto const& [key, list] : holdings_) {
		ret.push_back(key);
	}
	return ret;
}

namespace {

bool holds_completely(std::vector<data_holding> const& holdings, crypto::public_key_id const& holder) {
	auto const it = std::ranges::find(holdings, holder, &data_holding::holder);
	return it != holdings.end() && it->complete;
}

/// the rendezvous weight of a server for a data
octet_vector placement_weight(data_endpoint const& endpoint, data_id const& id) {
	octet_vector buf = endpoint.key.data();
	buf.insert(buf.end(), id.begin(), id.end());
	return crypto::hash(buf);
}

}

std::vector<data_endpoint> upload_order(std::vector<data_endpoint> endpoints, data_id const& id) {
	std::ranges::sort(endpoints, [&](data_endpoint const& a, data_endpoint const& b) {
		return placement_weight(a, id) < placement_weight(b, id);
	});
	return endpoints;
}

std::vector<data_endpoint> download_order(std::vector<data_endpoint> const& endpoints, data_id const& id
	, std::vector<data_holding> const& holdings, data_availability const& loads) {
	struct ranked {
		data_endpoint endpoint;
		// smaller sorts earlier: class (complete, partial, unknown), then the class's own measure
		int rank{};
		std::uint64_t first{};
		std::uint64_t second{};
	};

	std::vector<ranked> ranking;
	// the placement order breaks every tie and is the order of the unknown
	for(auto const& endpoint : upload_order(endpoints, id)) {
		ranked r{endpoint, 2, 0, 0};
		auto const it = std::ranges::find(holdings, endpoint.key, &data_holding::holder);
		if(it != holdings.end() && it->complete) {
			auto const load = loads.load(endpoint.key);
			r = ranked{endpoint, 0, load.uploads_in_progress, load.stored_bytes};
		} else if(it != holdings.end() && it->have_chunks != 0) {
			// more chunks first
			r = ranked{endpoint, 1, it->total_chunks - std::min(it->have_chunks, it->total_chunks), 0};
		}
		ranking.push_back(std::move(r));
	}
	std::ranges::stable_sort(ranking, [](ranked const& a, ranked const& b) {
		return std::tie(a.rank, a.first, a.second) < std::tie(b.rank, b.first, b.second);
	});

	std::vector<data_endpoint> ret;
	for(auto& r : ranking) {
		ret.push_back(std::move(r.endpoint));
	}
	return ret;
}

std::vector<data_endpoint> missing_copies(std::vector<data_endpoint> const& endpoints, data_id const& id
	, std::vector<data_holding> const& holdings, std::size_t copies) {
	std::vector<data_endpoint> ret;
	bool const held = std::ranges::any_of(endpoints, [&](data_endpoint const& e) { return holds_completely(holdings, e.key); });
	if(held) {
		auto primaries = upload_order(endpoints, id);
		primaries.resize(std::min(copies, primaries.size()));
		for(auto& primary : primaries) {
			if(!holds_completely(holdings, primary.key)) {
				ret.push_back(std::move(primary));
			}
		}
	}
	return ret;
}

std::vector<data_endpoint> replica_sources(std::vector<data_endpoint> const& endpoints, data_id const& id
	, std::vector<data_holding> const& holdings, data_availability const& loads, crypto::public_key_id const& target) {
	std::vector<data_endpoint> ret;
	for(auto& endpoint : download_order(endpoints, id, holdings, loads)) {
		if(endpoint.key != target && holds_completely(holdings, endpoint.key)) {
			ret.push_back(std::move(endpoint));
		}
	}
	return ret;
}

}
