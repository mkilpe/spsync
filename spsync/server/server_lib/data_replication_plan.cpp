#include "data_replication_plan.hpp"

#include <algorithm>

namespace securepath::sync {

namespace {

void plan_one(replication_view const& view, protocol::storage_id const& sid, data_id const& id, replication_plan& plan) {
	auto const holdings = view.availability.holdings(sid, id);
	bool const held = std::ranges::any_of(holdings, &data_holding::complete);
	if(held) {
		auto const standing = view.standing(sid, id);
		if(standing.dead) {
			plan.stale[sid].push_back(id);
		} else if(standing.descriptor) {
			for(auto const& target : missing_copies(view.data_servers, id, holdings, view.copies)) {
				if(view.reachable(target.key)) {
					plan.copies[target.key][sid].push_back(*standing.descriptor);
				}
			}
		}
	}
}

}

replication_plan plan_replication(replication_view const& view, std::vector<std::pair<protocol::storage_id, data_id>> const& data) {
	replication_plan plan;
	for(auto const& [sid, id] : data) {
		plan_one(view, sid, id, plan);
	}
	return plan;
}

}
