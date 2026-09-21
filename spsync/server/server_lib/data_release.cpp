#include "data_release.hpp"

#include <algorithm>

namespace securepath::sync {

std::vector<protocol::release_data> release_packets(protocol::storage_id const& sid
	, std::vector<data_id> const& ids, std::size_t batch)
{
	std::vector<protocol::release_data> ret;
	auto const size = std::max<std::size_t>(batch, 1);
	for(std::size_t first = 0; first < ids.size(); first += size) {
		auto const count = std::min(size, ids.size() - first);
		auto const begin = ids.begin() + static_cast<std::ptrdiff_t>(first);
		ret.emplace_back(sid, std::vector<data_id>(begin, begin + static_cast<std::ptrdiff_t>(count)));
	}
	return ret;
}

}
